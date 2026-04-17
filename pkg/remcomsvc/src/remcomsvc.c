/*
 * RemComSvc - Remote Command Service for gopacket psexec
 *
 * A Windows service that accepts commands over a named pipe,
 * executes them, and bridges stdin/stdout/stderr back to the caller
 * via per-session named pipes.
 *
 * Protocol:
 *   Client connects to \\.\pipe\RemCom_communicaton
 *   Client sends a 4628-byte message:
 *     [0..4095]    command (null-terminated string)
 *     [4096..4355] working directory (null-terminated string)
 *     [4356..4359] process priority (uint32 LE)
 *     [4360..4363] process ID / session key (uint32 LE)
 *     [4364..4623] machine identifier (null-terminated string)
 *     [4624..4627] no-wait flag (uint32 LE)
 *
 *   Service creates per-session pipes:
 *     \\.\pipe\RemCom_stdout<machine><pid>
 *     \\.\pipe\RemCom_stdin<machine><pid>
 *     \\.\pipe\RemCom_stderr<machine><pid>
 *
 *   Service spawns the process, bridges I/O, then writes an 8-byte response:
 *     [0..3] error code (uint32 LE)
 *     [4..7] process return code (uint32 LE)
 *
 * Build (mingw cross-compile from Linux):
 *   x86_64-w64-mingw32-gcc -O2 -s -o remcomsvc.exe remcomsvc.c -ladvapi32
 *
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define SERVICE_NAME        "RemComSvc"
#define COMM_PIPE_NAME      "\\\\.\\pipe\\RemCom_communicaton"
#define PIPE_PREFIX         "\\\\.\\pipe\\"
#define STDOUT_PREFIX       "RemCom_stdout"
#define STDIN_PREFIX        "RemCom_stdin"
#define STDERR_PREFIX       "RemCom_stderr"

#define MSG_SIZE            4628
#define CMD_OFFSET          0
#define CMD_LEN             4096
#define WORKDIR_OFFSET      4096
#define WORKDIR_LEN         260
#define PRIORITY_OFFSET     4356
#define PID_OFFSET          4360
#define MACHINE_OFFSET      4364
#define MACHINE_LEN         260
#define NOWAIT_OFFSET       4624

#define RESP_SIZE           8
#define PIPE_BUF            4096

/* Service globals */
static SERVICE_STATUS        g_status;
static SERVICE_STATUS_HANDLE g_status_handle;
static HANDLE                g_stop_event = NULL;

/* Forward declarations */
static void WINAPI service_main(DWORD argc, LPSTR *argv);
static void WINAPI service_ctrl(DWORD ctrl);
static void set_service_status(DWORD state, DWORD exit_code);
static void service_worker(void);
static DWORD handle_client(HANDLE comm_pipe);

/* I/O bridge thread context */
typedef struct {
    HANDLE read_handle;
    HANDLE write_handle;
} io_ctx_t;

static DWORD WINAPI io_bridge(LPVOID param)
{
    io_ctx_t *ctx = (io_ctx_t *)param;
    char buf[PIPE_BUF];
    DWORD nread, nwritten;

    while (ReadFile(ctx->read_handle, buf, sizeof(buf), &nread, NULL) && nread > 0) {
        if (!WriteFile(ctx->write_handle, buf, nread, &nwritten, NULL))
            break;
    }
    return 0;
}

/* Build a pipe name: \\.\pipe\<prefix><machine><pid> */
static void build_pipe_name(char *out, size_t out_sz,
                            const char *prefix, const char *machine, DWORD pid)
{
    char pid_str[12];
    DWORD i = 0, n = pid;

    /* uint32 to decimal string */
    if (n == 0) {
        pid_str[0] = '0';
        pid_str[1] = '\0';
    } else {
        char tmp[12];
        DWORD j = 0;
        while (n > 0) {
            tmp[j++] = (char)('0' + (n % 10));
            n /= 10;
        }
        for (i = 0; i < j; i++)
            pid_str[i] = tmp[j - 1 - i];
        pid_str[j] = '\0';
    }

    lstrcpynA(out, PIPE_PREFIX, (int)out_sz);
    lstrcatA(out, prefix);
    lstrcatA(out, machine);
    lstrcatA(out, pid_str);
}

/* Create a named pipe server and wait for a client connection */
static HANDLE create_and_connect_pipe(const char *name)
{
    HANDLE h = CreateNamedPipeA(
        name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,          /* max instances */
        PIPE_BUF,   /* out buffer */
        PIPE_BUF,   /* in buffer */
        0,          /* default timeout */
        NULL        /* default security */
    );
    if (h == INVALID_HANDLE_VALUE)
        return INVALID_HANDLE_VALUE;

    if (!ConnectNamedPipe(h, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        CloseHandle(h);
        return INVALID_HANDLE_VALUE;
    }
    return h;
}

/* Read exactly 'count' bytes from a handle */
static BOOL read_exact(HANDLE h, void *buf, DWORD count)
{
    DWORD total = 0, nread;
    while (total < count) {
        if (!ReadFile(h, (char *)buf + total, count - total, &nread, NULL) || nread == 0)
            return FALSE;
        total += nread;
    }
    return TRUE;
}

/* Read a little-endian uint32 from a buffer */
static DWORD read_u32(const unsigned char *p)
{
    return (DWORD)p[0] | ((DWORD)p[1] << 8) |
           ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

/* Write a little-endian uint32 to a buffer */
static void write_u32(unsigned char *p, DWORD v)
{
    p[0] = (unsigned char)(v);
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

static DWORD handle_client(HANDLE comm_pipe)
{
    unsigned char msg[MSG_SIZE];
    unsigned char resp[RESP_SIZE];
    char command[CMD_LEN];
    char workdir[WORKDIR_LEN];
    char machine[MACHINE_LEN];
    DWORD priority, pid, no_wait;
    char stdout_name[512], stdin_name[512], stderr_name[512];
    HANDLE h_stdout_pipe, h_stdin_pipe, h_stderr_pipe;
    HANDLE h_proc_stdin_rd, h_proc_stdin_wr;
    HANDLE h_proc_stdout_rd, h_proc_stdout_wr;
    HANDLE h_proc_stderr_rd, h_proc_stderr_wr;
    SECURITY_ATTRIBUTES sa;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    HANDLE threads[3];
    io_ctx_t stdout_ctx, stderr_ctx, stdin_ctx;
    DWORD exit_code = 0, error_code = 0;

    /* Read the command message */
    if (!read_exact(comm_pipe, msg, MSG_SIZE))
        return 1;

    /* Parse fields */
    CopyMemory(command, msg + CMD_OFFSET, CMD_LEN);
    command[CMD_LEN - 1] = '\0';

    CopyMemory(workdir, msg + WORKDIR_OFFSET, WORKDIR_LEN);
    workdir[WORKDIR_LEN - 1] = '\0';

    CopyMemory(machine, msg + MACHINE_OFFSET, MACHINE_LEN);
    machine[MACHINE_LEN - 1] = '\0';

    priority = read_u32(msg + PRIORITY_OFFSET);
    pid      = read_u32(msg + PID_OFFSET);
    no_wait  = read_u32(msg + NOWAIT_OFFSET);

    if (priority == 0)
        priority = NORMAL_PRIORITY_CLASS;

    /* Build per-session pipe names */
    build_pipe_name(stdout_name, sizeof(stdout_name), STDOUT_PREFIX, machine, pid);
    build_pipe_name(stdin_name,  sizeof(stdin_name),  STDIN_PREFIX,  machine, pid);
    build_pipe_name(stderr_name, sizeof(stderr_name), STDERR_PREFIX, machine, pid);

    /* Create per-session named pipes and wait for client */
    h_stdout_pipe = create_and_connect_pipe(stdout_name);
    h_stdin_pipe  = create_and_connect_pipe(stdin_name);
    h_stderr_pipe = create_and_connect_pipe(stderr_name);

    if (h_stdout_pipe == INVALID_HANDLE_VALUE ||
        h_stdin_pipe  == INVALID_HANDLE_VALUE ||
        h_stderr_pipe == INVALID_HANDLE_VALUE) {
        error_code = GetLastError();
        goto cleanup_pipes;
    }

    /* Create anonymous pipes for process I/O redirection */
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    if (!CreatePipe(&h_proc_stdin_rd, &h_proc_stdin_wr, &sa, 0) ||
        !CreatePipe(&h_proc_stdout_rd, &h_proc_stdout_wr, &sa, 0) ||
        !CreatePipe(&h_proc_stderr_rd, &h_proc_stderr_wr, &sa, 0)) {
        error_code = GetLastError();
        goto cleanup_pipes;
    }

    /* Ensure our side of the anonymous pipes isn't inherited */
    SetHandleInformation(h_proc_stdin_wr, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(h_proc_stdout_rd, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(h_proc_stderr_rd, HANDLE_FLAG_INHERIT, 0);

    /* Create the process */
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput  = h_proc_stdin_rd;
    si.hStdOutput = h_proc_stdout_wr;
    si.hStdError  = h_proc_stderr_wr;

    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(
            NULL,
            command,
            NULL, NULL,
            TRUE,       /* inherit handles */
            priority | CREATE_NO_WINDOW,
            NULL,
            workdir[0] ? workdir : NULL,
            &si, &pi)) {
        error_code = GetLastError();
        goto cleanup_anon;
    }

    /* Close the child's side of the anonymous pipes */
    CloseHandle(h_proc_stdin_rd);  h_proc_stdin_rd  = NULL;
    CloseHandle(h_proc_stdout_wr); h_proc_stdout_wr = NULL;
    CloseHandle(h_proc_stderr_wr); h_proc_stderr_wr = NULL;

    /* Bridge I/O between named pipes and process pipes */
    /* stdout: process stdout -> client stdout pipe */
    stdout_ctx.read_handle  = h_proc_stdout_rd;
    stdout_ctx.write_handle = h_stdout_pipe;
    threads[0] = CreateThread(NULL, 0, io_bridge, &stdout_ctx, 0, NULL);

    /* stderr: process stderr -> client stderr pipe */
    stderr_ctx.read_handle  = h_proc_stderr_rd;
    stderr_ctx.write_handle = h_stderr_pipe;
    threads[1] = CreateThread(NULL, 0, io_bridge, &stderr_ctx, 0, NULL);

    /* stdin: client stdin pipe -> process stdin */
    stdin_ctx.read_handle  = h_stdin_pipe;
    stdin_ctx.write_handle = h_proc_stdin_wr;
    threads[2] = CreateThread(NULL, 0, io_bridge, &stdin_ctx, 0, NULL);

    if (no_wait) {
        /* Don't wait for process, just report success */
        exit_code = 0;
        error_code = 0;
    } else {
        /* Wait for process to exit */
        WaitForSingleObject(pi.hProcess, INFINITE);
        GetExitCodeProcess(pi.hProcess, &exit_code);

        /* Wait for I/O threads to drain */
        WaitForMultipleObjects(2, threads, TRUE, 5000); /* stdout + stderr */
    }

    /* Clean up process */
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    /* Close our side of anonymous pipes to unblock I/O threads */
    if (h_proc_stdout_rd) CloseHandle(h_proc_stdout_rd);
    if (h_proc_stderr_rd) CloseHandle(h_proc_stderr_rd);
    if (h_proc_stdin_wr)  CloseHandle(h_proc_stdin_wr);
    h_proc_stdout_rd = h_proc_stderr_rd = h_proc_stdin_wr = NULL;

    /* Wait for stdin thread to finish */
    if (threads[2]) WaitForSingleObject(threads[2], 2000);

    /* Close thread handles */
    if (threads[0]) CloseHandle(threads[0]);
    if (threads[1]) CloseHandle(threads[1]);
    if (threads[2]) CloseHandle(threads[2]);

    goto send_response;

cleanup_anon:
    if (h_proc_stdin_rd)  CloseHandle(h_proc_stdin_rd);
    if (h_proc_stdin_wr)  CloseHandle(h_proc_stdin_wr);
    if (h_proc_stdout_rd) CloseHandle(h_proc_stdout_rd);
    if (h_proc_stdout_wr) CloseHandle(h_proc_stdout_wr);
    if (h_proc_stderr_rd) CloseHandle(h_proc_stderr_rd);
    if (h_proc_stderr_wr) CloseHandle(h_proc_stderr_wr);

send_response:
    /* Send response */
    write_u32(resp, error_code);
    write_u32(resp + 4, exit_code);
    {
        DWORD nwritten;
        WriteFile(comm_pipe, resp, RESP_SIZE, &nwritten, NULL);
    }

cleanup_pipes:
    if (h_stdout_pipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(h_stdout_pipe);
        CloseHandle(h_stdout_pipe);
    }
    if (h_stdin_pipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(h_stdin_pipe);
        CloseHandle(h_stdin_pipe);
    }
    if (h_stderr_pipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(h_stderr_pipe);
        CloseHandle(h_stderr_pipe);
    }

    return 0;
}

static void service_worker(void)
{
    HANDLE comm_pipe;

    while (WaitForSingleObject(g_stop_event, 0) != WAIT_OBJECT_0) {

        comm_pipe = CreateNamedPipeA(
            COMM_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUF,
            PIPE_BUF,
            0,
            NULL
        );

        if (comm_pipe == INVALID_HANDLE_VALUE)
            break;

        /* Wait for a client to connect */
        if (ConnectNamedPipe(comm_pipe, NULL) ||
            GetLastError() == ERROR_PIPE_CONNECTED) {
            handle_client(comm_pipe);
        }

        DisconnectNamedPipe(comm_pipe);
        CloseHandle(comm_pipe);
    }
}

static void set_service_status(DWORD state, DWORD exit_code)
{
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = exit_code;
    SetServiceStatus(g_status_handle, &g_status);
}

static void WINAPI service_ctrl(DWORD ctrl)
{
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        set_service_status(SERVICE_STOP_PENDING, 0);
        if (g_stop_event)
            SetEvent(g_stop_event);
    }
}

static void WINAPI service_main(DWORD argc, LPSTR *argv)
{
    (void)argc;
    (void)argv;

    g_status.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;

    g_status_handle = RegisterServiceCtrlHandlerA(SERVICE_NAME, service_ctrl);
    if (!g_status_handle)
        return;

    g_stop_event = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!g_stop_event) {
        set_service_status(SERVICE_STOPPED, GetLastError());
        return;
    }

    set_service_status(SERVICE_RUNNING, 0);

    service_worker();

    CloseHandle(g_stop_event);
    set_service_status(SERVICE_STOPPED, 0);
}

int main(void)
{
    SERVICE_TABLE_ENTRYA table[] = {
        { SERVICE_NAME, service_main },
        { NULL, NULL }
    };
    StartServiceCtrlDispatcherA(table);
    return 0;
}
