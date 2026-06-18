// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const SE_PRIVILEGE_DISABLED = win32.TOKEN_PRIVILEGES_ATTRIBUTES{};

const std = @import("std");
const win32 = @import("win32").everything;
const win32_security = @import("win32").security;

// https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170
const windows = std.os.windows;

// https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
const PRIVILEGES = [_][]const u8{
    win32.SE_CREATE_TOKEN_NAME,
    win32.SE_ASSIGNPRIMARYTOKEN_NAME,
    win32.SE_LOCK_MEMORY_NAME,
    win32.SE_INCREASE_QUOTA_NAME,
    win32.SE_UNSOLICITED_INPUT_NAME,
    win32.SE_MACHINE_ACCOUNT_NAME,
    win32.SE_TCB_NAME,
    win32.SE_SECURITY_NAME,
    win32.SE_TAKE_OWNERSHIP_NAME,
    win32.SE_LOAD_DRIVER_NAME,
    win32.SE_SYSTEM_PROFILE_NAME,
    win32.SE_SYSTEMTIME_NAME,
    win32.SE_PROF_SINGLE_PROCESS_NAME,
    win32.SE_INC_BASE_PRIORITY_NAME,
    win32.SE_CREATE_PAGEFILE_NAME,
    win32.SE_CREATE_PERMANENT_NAME,
    win32.SE_BACKUP_NAME,
    win32.SE_RESTORE_NAME,
    win32.SE_SHUTDOWN_NAME,
    win32.SE_DEBUG_NAME,
    win32.SE_AUDIT_NAME,
    win32.SE_SYSTEM_ENVIRONMENT_NAME,
    win32.SE_CHANGE_NOTIFY_NAME,
    win32.SE_REMOTE_SHUTDOWN_NAME,
    win32.SE_UNDOCK_NAME,
    win32.SE_SYNC_AGENT_NAME,
    win32.SE_ENABLE_DELEGATION_NAME,
    win32.SE_MANAGE_VOLUME_NAME,
    win32.SE_IMPERSONATE_NAME,
    win32.SE_CREATE_GLOBAL_NAME,
    win32.SE_TRUSTED_CREDMAN_ACCESS_NAME,
    win32.SE_RELABEL_NAME,
    win32.SE_INC_WORKING_SET_NAME,
    win32.SE_TIME_ZONE_NAME,
    win32.SE_CREATE_SYMBOLIC_LINK_NAME,
    win32.SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME,
};

// This exists until zigwin32 is updated to enable bitmasks for DesiredAccess /-:
extern "advapi32" fn OpenProcessToken(
    ProcessHandle: ?win32.HANDLE,
    DesiredAccess: win32_security.TOKEN_ACCESS_MASK,
    TokenHandle: ?*?win32.HANDLE,
) callconv(windows.WINAPI) win32.BOOL;

const Action = struct {
    const Self = @This();

    privilege: std.AutoHashMap(u32, u32),
    token: ?win32.HANDLE,
    hProcess: ?win32.HANDLE,
    targetPID: u32,
    enable: bool,
    remove: bool,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .privilege = std.AutoHashMap(u32, u32).init(allocator),
            .token = undefined,
            .hProcess = undefined,
            .targetPID = 0,
            .enable = true,
            .remove = false,
            .allocator = allocator,
        };
    }

    pub fn attemptModifyPrivilege(self: *Self) void {
        var tp: win32.TOKEN_PRIVILEGES = std.mem.zeroes(win32.TOKEN_PRIVILEGES);
        var result: u32 = 0;

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = win32.SE_PRIVILEGE_ENABLED;

        if (self.remove) {
            tp.Privileges[0].Attributes = win32.SE_PRIVILEGE_REMOVED;
        }
        if (!self.enable) {
            tp.Privileges[0].Attributes = SE_PRIVILEGE_DISABLED;
        }

        var idx: u32 = 0;
        for (PRIVILEGES) |privilege| {
            idx += 1;
            // If modification of specific privilege('s) is desired
            if (self.privilege.count() > 0 and !self.privilege.contains(idx - 1)) {
                continue;
            }

            const lpName = std.fmt.allocPrintSentinel(self.allocator, "{s}", .{privilege}, 0) catch return;
            defer self.allocator.free(lpName);

            // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluea
            if (0 == win32.LookupPrivilegeValueA(
                @ptrFromInt(0),
                lpName,
                &tp.Privileges[0].Luid,
            )) {
                std.log.err("[!] Failed LookupPrivilegeValueA :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
                continue;
            }

            // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
            if (0 == win32.AdjustTokenPrivileges(
                self.token,
                0,
                &tp,
                @sizeOf(win32.TOKEN_PRIVILEGES),
                @ptrFromInt(0),
                @ptrFromInt(0),
            )) {
                result = @intFromEnum(win32.GetLastError());
                if (result == @intFromEnum(win32.WIN32_ERROR.ERROR_INVALID_HANDLE)) {
                    std.log.err("[!] Failed AdjustTokenPrivileges {s} - invalid handle :: error code ({d})", .{ privilege, result });
                    break;
                } else {
                    std.log.err("[!] Failed AdjustTokenPrivileges {s} :: error code ({d})", .{ privilege, result });
                }
            }

            result = @intFromEnum(win32.GetLastError());
            if (result != 0) {
                if (result == 1300) { // win32.WIN32_ERROR.ERROR_NOT_ALL_ASSIGNED
                    std.log.err("[!] Failed to modify privilege {s} :: error code ({d})", .{ privilege, result });
                } else {
                    std.log.err("[-] Failed to modify {s} :: error code ({d})", .{ privilege, result });
                }
            } else {
                std.log.info("[+] Modified {s}", .{privilege});
            }
        }
    }

    pub fn getToken(self: *Self) bool {
        if (self.targetPID == 0) {
            self.targetPID = Action.PPID();
        }

        if (self.targetPID == 0) {
            std.log.err("[!] Failed to locate parent process Id :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        std.log.debug("[+] OpenProcess({d})", .{self.targetPID});

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        self.hProcess = win32.OpenProcess(
            win32.PROCESS_QUERY_LIMITED_INFORMATION,
            windows.TRUE,
            self.targetPID,
        );
        defer _ = Action.CloseHandle(self.hProcess);
        const result = @intFromEnum(win32.GetLastError());

        if (result != 0) {
            std.log.err("[!] Failed OpenProcess :: error code ({d})", .{result});
            return false;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        if (0 == OpenProcessToken(
            self.hProcess.?,
            win32_security.TOKEN_ALL_ACCESS,
            &self.token,
        )) {
            std.log.err("[!] Failed OpenProcessToken :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        return true;
    }

    pub fn debug(self: *Self) void {
        std.log.info(
            "\nModify Privileges for PID :: {d}\n",
            .{self.targetPID},
        );
        var itr = self.privilege.keyIterator();

        while (itr.next()) |k| {
            std.log.info("\t{d} == {s}", .{ k.*, PRIVILEGES[k.*] });
        }
        std.log.info("\n", .{});
    }

    pub fn parsePID(self: *Self, line: []u8) !void {
        self.targetPID = std.fmt.parseInt(u32, line, 10) catch undefined;
    }

    pub fn parsePrivileges(self: *Self, line: []u8) !void {
        var possible = std.mem.tokenizeSequence(u8, line, ",");

        while (possible.next()) |id| {
            const value = std.fmt.parseUnsigned(u32, id, 10) catch |err| {
                std.log.debug("E {any}\n", .{err});
                return;
            };
            self.privilege.put(value, 1) catch |err| {
                std.log.debug("E {any}\n", .{err});
                return;
            };
        }
    }

    pub fn deinit(self: *Self) void {
        self.privilege.deinit();
        Action.CloseHandle(self.hProcess);

        // https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-reverttoself
        _ = win32.RevertToSelf();
    }

    pub fn CloseHandle(handle: ?win32.HANDLE) void {
        if (handle != null and handle.? != win32.INVALID_HANDLE_VALUE) {
            // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
            _ = win32.CloseHandle(handle.?);
        }
    }

    pub fn PPID() u32 {
        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid
        const pid: u32 = win32.GetCurrentProcessId();

        //https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
        const handle = win32.CreateToolhelp32Snapshot(
            win32.TH32CS_SNAPPROCESS,
            0,
        );

        if (handle == win32.INVALID_HANDLE_VALUE) {
            return 0;
        }

        defer Action.CloseHandle(handle);

        var pe32: win32.PROCESSENTRY32 = std.mem.zeroes(win32.PROCESSENTRY32);
        pe32.dwSize = @sizeOf(win32.PROCESSENTRY32);

        // https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
        if (windows.FALSE == win32.Process32First(
            handle,
            &pe32,
        )) {
            return 0;
        }

        if (pe32.th32ProcessID == pid) {
            return pe32.th32ParentProcessID;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next
        while (windows.TRUE == win32.Process32Next(
            handle,
            &pe32,
        )) {
            if (pe32.th32ProcessID == pid) {
                return pe32.th32ParentProcessID;
            }
        }

        return 0;
    }
};

pub fn usage(argv: []u8) !void {
    const stdout = std.io.getStdOut().writer();

    try stdout.print(
        \\  This tool exist thanks to https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1 and https://www.leeholmes.com/blog/2010/09/24/adjusting-token-privileges-in-powershell/
        \\
        \\Example:
        \\ Attempt to enable all privileges for the current process:
        \\ .\\{s}
        \\
        \\ Attempt to enable the privileges SeShutdown & SeTimeZone for the current process:
        \\ .\\{s} 0 18,33
        \\
        \\ Attempt to enable the privileges SeShutdown & SeTimeZone for the process where PID == 9001:
        \\ .\\{s} 9001 18,33
        \\
        \\ Attempt to disable the privileges SeShutdown & SeTimeZone for the process where PID == 9001:
        \\ .\\{s} 9001 18,33 -d
        \\
        \\ Attempt to remove the privileges SeShutdown & SeTimeZone for the process where PID == 9001:
        \\ .\\{s} 9001 18,33 -r
        \\
        \\ Show this menu
        \\ .\\{s} -h
        \\
    , .{ argv, argv, argv, argv, argv, argv });

    try stdout.print("\n", .{});
    for (PRIVILEGES, 0..) |privilege, idx| {
        try stdout.print("\t{d} = {s}\n", .{ idx, privilege });
    }
    try stdout.print("\n", .{});

    std.posix.exit(0);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // Parse args into string array (error union needs 'try')
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len > 4) {
        try usage(args[0]);
    }

    var action = try Action.init(allocator);
    defer action.deinit();

    var i: u8 = 0;

    for (args) |arg| {
        if (std.mem.containsAtLeast(u8, arg, 1, "-h") or std.mem.containsAtLeast(u8, arg, 1, "-H")) {
            try usage(args[0]);
            std.posix.exit(0);
        }

        if (std.mem.containsAtLeast(u8, arg, 1, "-d") or std.mem.containsAtLeast(u8, arg, 1, "-D")) {
            action.enable = false;
        }

        if (std.mem.containsAtLeast(u8, arg, 1, "-r") or std.mem.containsAtLeast(u8, arg, 1, "-R")) {
            action.remove = true;
        }

        if (i == 1) {
            try action.parsePID(arg);
        }

        if (i == 2) {
            try action.parsePrivileges(arg);
        }

        i += 1;
    }

    action.debug();

    if (!action.getToken()) {
        std.log.err("[!] Failed to get token for process", .{});
        return;
    }

    action.attemptModifyPrivilege();

    std.log.info("[+] Done", .{});

    std.posix.exit(0);
}
