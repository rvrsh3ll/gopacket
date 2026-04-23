// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Declarative NDR parser for DRS_MSG_GETCHGREPLY_V6 and its nested
// structures. Each helper mirrors an IDL struct from MS-DRSR and is
// written against the Decoder primitives in ndr.go, so the byte-level
// work is explicit rather than expressed via magic offsets.
//
// Structure map (MS-DRSR):
//
//   DRS_MSG_GETCHGREPLY_V6           4.1.10.2.11
//     pNC                -> DSNAME                  4.1.4.1.1
//     pUpToDateVecSrc    -> UPTODATE_VECTOR_V{1,2}  4.1.4.1.6 / 4.1.4.1.7
//     PrefixTableSrc     -> SCHEMA_PREFIX_TABLE     4.1.10.1.7
//     pObjects           -> REPLENTINFLIST*         4.1.10.1.9
//         Entinf         -> ENTINF                   5.58
//         pParentGuidm   -> UUID
//         pMetaDataExt   -> PROPERTY_META_DATA_EXT_VECTOR  4.2.2.1.3

package drsuapi

import (
	"encoding/binary"
	"strings"

	"github.com/mandiant/gopacket/pkg/utf16le"
)

// parseGetNCChangesResponseV6NDR parses the V6/V7/V9 GetNCChanges reply.
// V6 is the canonical shape; V7 and V9 add fields after the V6 body which
// this parser does not consume (same limitation as Impacket's secretsdump).
func parseGetNCChangesResponseV6NDR(resp []byte, sessionKey []byte) (*GetNCChangesResult, error) {
	d := NewDecoder(resp)
	result := &GetNCChangesResult{}

	// DRS_MSG_GETCHGREPLY header (inline portion). The enclosing response
	// was already consumed through outVersion; our Decoder starts at the
	// beginning of the payload, so we still skip 4 bytes of outVersion +
	// 4 bytes of union tag to land on the V6 fields.
	d.Skip(4) // outVersion, already read by caller
	d.Skip(4) // union tag

	// uuidDsaObjSrc (16) + uuidInvocIdSrc (16).
	d.Skip(16)
	d.Skip(16)

	ptrNC := d.ReadPointer()

	// usnvecFrom is a USN_VECTOR = 3 LONGLONGs. LONGLONG alignment is 8,
	// so we align before reading.
	d.Align(8)
	d.Skip(24) // usnvecFrom

	// usnvecTo: capture the high-water mark we return as the pagination
	// cursor. Three LONGLONGs.
	result.HighWaterMark.HighObjUpdate = d.ReadUint64()
	result.HighWaterMark.Reserved = d.ReadUint64()
	result.HighWaterMark.HighPropUpdate = d.ReadUint64()

	ptrUpToDate := d.ReadPointer()

	// PrefixTableSrc is a SCHEMA_PREFIX_TABLE inline: cNumPrefixes +
	// pPrefixEntry referent.
	prefixCount := d.ReadUint32()
	ptrPrefixEntry := d.ReadPointer()

	// The rest of the fixed V6 header.
	_ = d.ReadUint32() // ulExtendedRet
	numObjects := d.ReadUint32()
	_ = d.ReadUint32() // cNumBytes
	ptrObjects := d.ReadPointer()
	result.MoreData = d.ReadUint32() != 0
	_ = d.ReadUint32() // cNumNcSizeObjects (V6)
	_ = d.ReadUint32() // cNumNcSizeValues (V6)

	// Full V6 header also has cNumValues, rgValues, dwDRSError. Impacket
	// treats rgValues as an opaque DWORD (not a pointer with deferred
	// REPLVALINF_V1_ARRAY) because parsing REPLVALINF is broken in their
	// implementation too.
	_ = d.ReadUint32() // cNumValues
	_ = d.ReadUint32() // rgValues (opaque)
	_ = d.ReadUint32() // dwDRSError

	// Deferred data follows in pointer declaration order: pNC,
	// pUpToDateVecSrc, pPrefixEntry, pObjects.

	if ptrNC != 0 {
		skipDSNAMEv2(d)
	}
	if ptrUpToDate != 0 {
		skipUpToDateVectorV2(d)
	}

	prefixTable := make(map[uint32][]byte)
	if ptrPrefixEntry != 0 && prefixCount > 0 {
		readPrefixTableV2(d, prefixCount, prefixTable)
	}

	if ptrObjects != 0 {
		result.Objects = readREPLENTINFLISTArrayV2(d, sessionKey, prefixTable, numObjects)
	}

	return result, d.Err()
}

// skipDSNAMEv2 consumes a DSNAME deferred struct without capturing values.
// DSNAME is a conformant struct (StringName is an NDRUniConformantArray, not
// conformant-varying); wire layout is MaxCount + structLen + SidLen + Guid
// + Sid + NameLen + StringName[MaxCount].
func skipDSNAMEv2(d *Decoder) {
	maxCount := d.ReadConformance()
	_ = d.ReadUint32() // structLen
	_ = d.ReadUint32() // SidLen
	d.Skip(16)         // Guid
	d.Skip(28)         // Sid
	_ = d.ReadUint32() // NameLen
	d.Skip(int(maxCount) * 2)
	d.Align(4)
}

// readDSNAMEv2 parses a DSNAME and fills the given ReplicatedObject's
// GUID, ObjectSid, RID, and DN fields. Same layout as skipDSNAMEv2.
func readDSNAMEv2(d *Decoder, obj *ReplicatedObject) {
	maxCount := d.ReadConformance()
	_ = d.ReadUint32() // structLen
	sidLen := d.ReadUint32()
	copy(obj.GUID[:], d.ReadBytes(16))
	sid := d.ReadBytes(28)
	if sidLen > 0 && sidLen <= 28 && sid != nil {
		obj.ObjectSid = append([]byte(nil), sid[:sidLen]...)
		if sidLen >= 8 {
			obj.RID = binary.LittleEndian.Uint32(sid[sidLen-4:])
		}
	}
	nameLen := d.ReadUint32()
	if maxCount > 0 {
		name := d.ReadBytes(int(maxCount) * 2)
		if name != nil {
			visible := name
			if nameLen > 0 && int(nameLen)*2 <= len(name) {
				visible = name[:nameLen*2]
			}
			obj.DN = utf16le.DecodeToString(visible)
			for len(obj.DN) > 0 && obj.DN[len(obj.DN)-1] == 0 {
				obj.DN = obj.DN[:len(obj.DN)-1]
			}
		}
	}
	d.Align(4)
}

// skipUpToDateVectorV2 consumes the deferred UPTODATE_VECTOR_V{1,2}_EXT.
// Both V1 and V2 share the same header (dwVersion, dwReserved1, cNumCursors,
// dwReserved2); cursors are UUID + USN (24 bytes) in V1, UUID + USN + DSTIME
// (32 bytes) in V2. NDR early conformance puts MaxCount at the front.
func skipUpToDateVectorV2(d *Decoder) {
	_ = d.ReadConformance() // MaxCount
	version := d.ReadUint32()
	_ = d.ReadUint32() // dwReserved1
	cNumCursors := d.ReadUint32()
	_ = d.ReadUint32() // dwReserved2

	cursorSize := 24
	if version == 2 {
		cursorSize = 32
	}
	d.Skip(int(cNumCursors) * cursorSize)
}

// readPrefixTableV2 consumes the PrefixTableEntry_ARRAY deferred data
// (conformant array of {ndx: DWORD, prefix: OID_t}) and populates the
// prefixTable map with ndx -> OID bytes for decoding attribute type IDs.
func readPrefixTableV2(d *Decoder, count uint32, prefixTable map[uint32][]byte) {
	_ = d.ReadConformance() // MaxCount of the PrefixTableEntry array

	type entry struct {
		ndx       uint32
		oidLen    uint32
		oidPtrRef uint32
	}
	entries := make([]entry, count)
	for i := uint32(0); i < count; i++ {
		entries[i].ndx = d.ReadUint32()
		entries[i].oidLen = d.ReadUint32()
		entries[i].oidPtrRef = d.ReadPointer()
	}

	for i := range entries {
		if entries[i].oidPtrRef == 0 || entries[i].oidLen == 0 {
			continue
		}
		oidMaxCount := d.ReadConformance()
		oidBytes := d.ReadBytes(int(oidMaxCount))
		if oidBytes != nil {
			prefixTable[entries[i].ndx] = append([]byte(nil), oidBytes...)
		}
		d.Align(4)
	}
}

// skipPropertyMetaDataExtVectorV2 consumes a PROPERTY_META_DATA_EXT_VECTOR
// deferred struct.
//
// PROPERTY_META_DATA_EXT_VECTOR (MS-DRSR 4.2.2.1.3):
//
//	DWORD cNumProps
//	[size_is(cNumProps)] PROPERTY_META_DATA_EXT rgMetaData[]
//
// Each PROPERTY_META_DATA_EXT (MS-DRSR 4.2.2.1.4):
//
//	DWORD  dwVersion          (4)
//	DSTIME timeChanged        (8, LONGLONG)
//	UUID   uuidDsaOriginating (16)
//	USN    usnOriginating     (8, LONGLONG)
//
// DSTIME and USN force 8-byte alignment for the element, so struct alignment
// is also 8. NDR early-conformance hoists rgMetaData's MaxCount to the front,
// but the hoisted MaxCount uses only its primitive (4-byte) alignment; the
// struct's 8-byte alignment is applied AFTER MaxCount before the struct's
// other fields. Wire layout is:
//
//	[pad to 4] MaxCount(4) [pad to 8] cNumProps(4) [pad to 8] elements[MaxCount]
//
// Each element is 40 bytes: dwVersion(4) + pad(4) + timeChanged(8) +
// uuidDsaOriginating(16) + usnOriginating(8). The amount of padding inserted
// depends on where the decoder landed after the preceding pParent UUID, which
// is 4-aligned rather than 8-aligned.
func skipPropertyMetaDataExtVectorV2(d *Decoder) {
	maxCount := d.ReadUint32() // hoisted conformance, 4-aligned
	d.Align(8)                 // struct alignment before cNumProps
	_ = d.ReadUint32()         // cNumProps
	d.Align(8)                 // element alignment
	const metaDataExtSize = 40
	d.Skip(int(maxCount) * metaDataExtSize)
}

// readREPLENTINFLISTArrayV2 parses the linked-list of REPLENTINFLIST entries
// pointed to by pObjects. REPLENTINFLIST is a self-referential struct with
// pNextEntInf (first field) threading the list, plus Entinf, fIsNCPrefix,
// pParentGuidm, and pMetaDataExt. NDR serializes this via strict DFS through
// pNext: all N fixed parts come first (since pNext is always the first
// pointer encountered in each node), then the non-pNext deferreds unwind
// bottom-up — the deepest node's pName/pAttr/pParent/pMeta appear first,
// the head node's appear last. So to match the wire we must iterate the
// captured headers in reverse.
func readREPLENTINFLISTArrayV2(d *Decoder, sessionKey []byte, prefixTable map[uint32][]byte, numObjects uint32) []ReplicatedObject {
	type header struct {
		ptrNext       uint32
		ptrName       uint32
		flags         uint32
		attrCount     uint32
		ptrAttr       uint32
		isNCPrefix    uint32
		ptrParentGuid uint32
		ptrMetaData   uint32
	}

	headers := make([]header, numObjects)
	for i := uint32(0); i < numObjects; i++ {
		headers[i].ptrNext = d.ReadPointer()
		headers[i].ptrName = d.ReadPointer()
		headers[i].flags = d.ReadUint32()
		headers[i].attrCount = d.ReadUint32()
		headers[i].ptrAttr = d.ReadPointer()
		headers[i].isNCPrefix = d.ReadUint32()
		headers[i].ptrParentGuid = d.ReadPointer()
		headers[i].ptrMetaData = d.ReadPointer()
	}

	objects := make([]ReplicatedObject, 0, numObjects)
	for i := int(numObjects) - 1; i >= 0; i-- {
		h := headers[i]
		obj := ReplicatedObject{}

		if h.ptrName != 0 {
			readDSNAMEv2(d, &obj)
		}
		if h.ptrAttr != 0 && h.attrCount > 0 {
			readATTRBLOCKv2(d, &obj, sessionKey, prefixTable)
		}
		if h.ptrParentGuid != 0 {
			d.ReadGUID()
		}
		if h.ptrMetaData != 0 {
			skipPropertyMetaDataExtVectorV2(d)
		}

		if obj.SAMAccountName == "" && strings.HasPrefix(obj.DN, "CN=") {
			rdn := obj.DN[3:]
			if comma := strings.IndexByte(rdn, ','); comma >= 0 {
				rdn = rdn[:comma]
			}
			obj.SAMAccountName = rdn
		}

		if obj.SAMAccountName != "" || len(obj.NTHash) > 0 {
			objects = append(objects, obj)
		}
	}

	return objects
}

// readATTRBLOCKv2 consumes a deferred ATTR_ARRAY. Layout is: MaxCount + N
// ATTR fixed parts (attrTyp, valCount, pAVal), then for each non-null pAVal
// the deferred ATTRVAL_ARRAY, which itself is MaxCount + N (valLen, pVal)
// fixed parts followed by each pVal's deferred byte array.
//
// prefixTable is accepted for future use (attribute-type OID expansion);
// processAttribute works on the raw numeric attrTyp today.
func readATTRBLOCKv2(d *Decoder, obj *ReplicatedObject, sessionKey []byte, prefixTable map[uint32][]byte) {
	_ = prefixTable

	const maxReasonable = 10 * 1024 * 1024
	arrayMax := d.ReadConformance()
	if arrayMax > maxReasonable {
		return
	}

	type attrFixed struct {
		attrTyp uint32
		ptrAVal uint32
	}
	attrs := make([]attrFixed, arrayMax)
	for i := uint32(0); i < arrayMax; i++ {
		attrs[i].attrTyp = d.ReadUint32()
		_ = d.ReadUint32() // valCount (ignored; wire conformance is authoritative)
		attrs[i].ptrAVal = d.ReadPointer()
	}

	for i := uint32(0); i < arrayMax; i++ {
		if attrs[i].ptrAVal == 0 {
			continue
		}
		valMax := d.ReadConformance()
		if valMax > maxReasonable {
			return
		}
		vals := make([]uint32, valMax)
		for j := uint32(0); j < valMax; j++ {
			_ = d.ReadUint32() // valLen
			vals[j] = d.ReadPointer()
		}
		for j := uint32(0); j < valMax; j++ {
			if vals[j] == 0 {
				continue
			}
			byteMax := d.ReadConformance()
			if byteMax > maxReasonable {
				return
			}
			valData := d.ReadBytes(int(byteMax))
			if valData != nil {
				processAttribute(attrs[i].attrTyp, append([]byte(nil), valData...), obj, sessionKey)
			}
			d.Align(4)
		}
	}
}
