// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};
const utility = @import("lib/utility.zig");

const std = @import("std");
const win32 = @import("win32").everything;
const windows = std.os.windows;

const Action = struct {
    const Self = @This();

    const Error = error{
        UnknownError,
    };

    allocator: std.mem.Allocator,
    sessionID: i32,
    command: [:0]u8,
    silent: bool,

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .allocator = allocator,
            .sessionID = undefined,
            .command = undefined,
            .silent = false,
        };
    }

    pub fn attemptExecInSession(self: *Self) !void {
        // https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsenumeratesessionsa
        var ppSessionInfo: ?*win32.WTS_SESSION_INFOA = undefined;
        var pCount: u32 = 0;

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid
        const myPID: u32 = win32.GetCurrentProcessId();
        var mySessionId: u32 = 0;
        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-processidtosessionid
        if (0 == win32.ProcessIdToSessionId(myPID, &mySessionId)) {
            return Error.UnknownError;
        }

        std.log.info("[+] Current session ID: {d}", .{mySessionId});

        if (0 == win32.WTSEnumerateSessionsA(@ptrFromInt(0), 0, 1, @constCast(&ppSessionInfo), &pCount)) {
            return Error.UnknownError;
        }

        std.log.debug("[+] Session Count: {d}", .{pCount});

        defer win32.WTSFreeMemory(ppSessionInfo);

        const sessions: [*]win32.WTS_SESSION_INFOA = @ptrCast(ppSessionInfo.?);

        var idx: u32 = 0;
        while (idx < pCount) : (idx += 1) {
            std.log.debug("[+] Found session with ID: {d}", .{sessions[idx].SessionId});

            if (sessions[idx].SessionId == 0) {
                std.log.debug("[!] Skipping session 0", .{});
                continue;
            }

            if (sessions[idx].SessionId == mySessionId) {
                std.log.debug("[!] Skipping session with ID {d}", .{mySessionId});
                continue;
            }

            if (sessions[idx].SessionId == self.sessionID or self.sessionID == -1) {
                std.log.debug("[+] Evaluating session with ID: {d}", .{sessions[idx].SessionId});

                switch (sessions[idx].State) {
                    win32.WTSActive, win32.WTSConnected, win32.WTSConnectQuery, win32.WTSShadow, win32.WTSDisconnected, win32.WTSIdle => {
                        std.log.info("[+] Selecting sesssion with ID: {d}", .{sessions[idx].SessionId});

                        self.executeCommandInSession(sessions[idx].SessionId) catch |err| {
                            std.log.err("[!] Failed to execute {s} in session ID {d} due to {any}", .{ self.command, sessions[idx].SessionId, err });
                        };
                    },
                    else => {
                        std.log.info("[-] Skipping session ID: {d}", .{sessions[idx].SessionId});
                        continue;
                    },
                }
            }
        }
    }

    fn executeCommandInSession(self: *Self, sessionId: u32) !void {
        std.log.debug("[+] Attempting execution of command: {s}\n\tUsing Session ID: {d}\n", .{ self.command, sessionId });

        // https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken

        var phToken: ?win32.HANDLE = null;
        if (0 == win32.WTSQueryUserToken(sessionId, &phToken)) {
            std.log.err("ExecuteCommandInSession: WTSQueryUserToken: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return Error.UnknownError;
        }
        defer utility.closeHandle(phToken);

        var lpProcessAttributes: win32.SECURITY_ATTRIBUTES = std.mem.zeroes(win32.SECURITY_ATTRIBUTES);
        lpProcessAttributes.nLength = @sizeOf(win32.SECURITY_ATTRIBUTES);
        lpProcessAttributes.bInheritHandle = windows.TRUE;

        var lpThreadAttributes: win32.SECURITY_ATTRIBUTES = std.mem.zeroes(win32.SECURITY_ATTRIBUTES);
        lpThreadAttributes.nLength = @sizeOf(win32.SECURITY_ATTRIBUTES);
        lpThreadAttributes.bInheritHandle = windows.TRUE;

        var stdinReadPipe: ?win32.HANDLE = null;
        var stdinWritePipe: ?win32.HANDLE = null;

        // https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe
        if (0 == win32.CreatePipe(
            &stdinReadPipe,
            &stdinWritePipe,
            &lpProcessAttributes,
            4096,
        )) {
            std.log.err("ExecuteCommandInSession: CreatePipe (stdout): {d}\n", .{@intFromEnum(win32.GetLastError())});
            return Error.UnknownError;
        }
        _ = win32.SetHandleInformation(stdinWritePipe, @bitCast(win32.HANDLE_FLAG_INHERIT), .{});

        var stdoutReadPipe: ?win32.HANDLE = null;
        var stdoutWritePipe: ?win32.HANDLE = null;

        // https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe
        if (0 == win32.CreatePipe(
            &stdoutReadPipe,
            &stdoutWritePipe,
            &lpProcessAttributes,
            4096,
        )) {
            std.log.err("ExecuteCommandInSession: CreatePipe (stdout): {d}\n", .{@intFromEnum(win32.GetLastError())});
            return Error.UnknownError;
        }
        defer utility.closeHandle(stdoutReadPipe);
        _ = win32.SetHandleInformation(stdoutReadPipe, @bitCast(win32.HANDLE_FLAG_INHERIT), .{});

        var stderrReadPipe: ?win32.HANDLE = null;
        var stderrWritePipe: ?win32.HANDLE = null;

        // https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createpipe
        if (0 == win32.CreatePipe(
            &stderrReadPipe,
            &stderrWritePipe,
            &lpProcessAttributes,
            4096,
        )) {
            std.log.err("ExecuteCommandInSession: CreatePipe (stderr): {d}\n", .{@intFromEnum(win32.GetLastError())});
            return Error.UnknownError;
        }
        defer utility.closeHandle(stderrReadPipe);
        _ = win32.SetHandleInformation(stderrReadPipe, @bitCast(win32.HANDLE_FLAG_INHERIT), .{});

        var si: win32.STARTUPINFOW = std.mem.zeroes(win32.STARTUPINFOW);
        si.cb = @sizeOf(win32.STARTUPINFOW);
        si.hStdInput = stdinReadPipe;
        si.hStdOutput = stdoutWritePipe;
        si.hStdError = stderrWritePipe;
        si.dwFlags = win32.STARTF_USESTDHANDLES;

        var pi: win32.PROCESS_INFORMATION = std.mem.zeroes(win32.PROCESS_INFORMATION);

        const powershell = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.exe";

        const commandLine = try std.fmt.allocPrintSentinel(self.allocator, "{s} -Command \"{s}\"", .{ powershell, self.command }, 0);
        defer self.allocator.free(commandLine);

        const lpCommandLine = std.unicode.utf8ToUtf16LeAllocZ(self.allocator, commandLine) catch undefined;
        errdefer self.allocator.free(lpCommandLine);

        if (0 == win32.ImpersonateLoggedOnUser(phToken)) {
            std.log.err("[!] ImpersonateLoggedOnUser failed", .{});
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasusera
        if (0 == win32.CreateProcessAsUserW(
            phToken,
            null, // lpApplicationName,
            @constCast(lpCommandLine.ptr),
            &lpProcessAttributes,
            &lpThreadAttributes,
            windows.TRUE,
            if (self.silent) @bitCast(win32.CREATE_NO_WINDOW) else 0,
            @ptrFromInt(0),
            null,
            &si,
            &pi,
        )) {
            std.log.err("CreateProcessAsUser: GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return Error.UnknownError;
        }
        _ = win32.RevertToSelf();

        std.log.info("[+] Spawned process in session ID: {d} with PID: {d} executing {s} -Command \"{s}\"", .{ sessionId, pi.dwProcessId, powershell, self.command });

        defer utility.closeHandle(pi.hProcess);
        defer utility.closeHandle(pi.hThread);

        // Close handles to the stdin and stdout pipes no longer needed by the child process.
        // If they are not explicitly closed, there is no way to recognize that the child process has ended.
        utility.closeHandle(stdinReadPipe);
        utility.closeHandle(stdinWritePipe);
        utility.closeHandle(stdoutWritePipe);
        utility.closeHandle(stderrWritePipe);

        const stdout = std.io.getStdOut().writer();
        const stderr = std.io.getStdErr().writer();

        const waiting: bool = if (self.silent) false else true;

        if (waiting) {
            std.log.info("[+] Waiting for output from PID: {d}\n\n", .{pi.dwProcessId});
        }

        while (waiting) {
            var lpBuffer: [4096]u8 = std.mem.zeroes([4096]u8);
            var lpNumberOfBytesRead: u32 = 0;

            // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
            _ = win32.ReadFile(
                stdoutReadPipe,
                &lpBuffer,
                4096,
                &lpNumberOfBytesRead,
                null,
            );

            if (lpNumberOfBytesRead > 0) {
                try stdout.print("{s}", .{lpBuffer[0..lpNumberOfBytesRead]});
            }

            lpBuffer = std.mem.zeroes([4096]u8);
            lpNumberOfBytesRead = 0;

            // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
            _ = win32.ReadFile(
                stderrReadPipe,
                &lpBuffer,
                4096,
                &lpNumberOfBytesRead,
                null,
            );

            if (lpNumberOfBytesRead > 0) {
                try stderr.print("{s}", .{lpBuffer[0..lpNumberOfBytesRead]});
            }

            const ret: win32.WIN32_ERROR = @enumFromInt(win32.WaitForSingleObject(pi.hProcess, 100));

            if (ret != win32.WAIT_TIMEOUT or ret == win32.WAIT_OBJECT_0) {
                break;
            }
        }

        try stdout.print("\n\n", .{});
    }

    pub fn debug(self: *Self) void {
        std.log.info("\nExecute {any} in Session ID: {d}\n", .{ self.command, self.sessionID });
        std.log.info("\n", .{});
    }

    pub fn parseCommand(self: *Self, line: []u8) !void {
        self.command = try std.fmt.allocPrintSentinel(self.allocator, "{s}", .{line}, 0);
        errdefer self.allocator.free(self.command);
    }

    pub fn parseSessionID(self: *Self, line: []u8) !void {
        self.sessionID = std.fmt.parseInt(i32, line, 10) catch undefined;
    }

    pub fn deinit(self: *Self) void {
        defer self.allocator.free(self.command);
    }
};

pub fn usage(argv: []u8) !void {
    const stdout = std.io.getStdOut().writer();

    try stdout.print(
        \\  This tool exist thanks to https://github.com/Leo4j/SessionExec/blob/main/SessionExec.cs
        \\
        \\Example:
        \\
        \\ Attempt to take ownership of PID for the user 'pete':
        \\ .\\{s} <SessionID|-1> <Command> [-s]
        \\
        \\ Show this menu
        \\ .\\{s} -h
        \\
    , .{ argv, argv });

    std.posix.exit(0);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // Parse args into string array (error union needs 'try')
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 3) {
        try usage(args[0]);
    }

    var action = try Action.init(allocator);
    defer action.deinit();

    var i: u8 = 0;

    for (args) |arg| {
        if (i == 1) {
            try action.parseSessionID(arg);
        }

        if (i == 2) {
            try action.parseCommand(arg);
        }

        if (std.mem.containsAtLeast(u8, arg, 1, "-s") or std.mem.containsAtLeast(u8, arg, 1, "-S")) {
            action.silent = true;
        }

        i += 1;
    }

    action.debug();

    try action.attemptExecInSession();

    std.log.info("\n\n[+] Done", .{});

    std.posix.exit(0);
}
