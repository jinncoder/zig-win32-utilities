// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const std = @import("std");
const win32 = @import("win32").everything;

// For POLICY_* see https://msdn.microsoft.com/en-us/library/windows/desktop/ms721916(v=vs.85).aspx
// Values found in https://github.com/Victek/Tomato-RAF/blob/99ea203ea065ce7c79b481ee590938c01e2ff824/release/src/router/samba3/source/include/rpc_lsa.h#L247-L291

const STANDARD_RIGHTS_READ: i32 = @bitCast(win32.STANDARD_RIGHTS_READ);
const POLICY_READ = STANDARD_RIGHTS_READ |
    win32.POLICY_VIEW_AUDIT_INFORMATION |
    win32.POLICY_GET_PRIVATE_INFORMATION;

const STANDARD_RIGHTS_WRITE: i32 = @bitCast(win32.STANDARD_RIGHTS_WRITE);
const POLICY_WRITE = STANDARD_RIGHTS_WRITE |
    win32.POLICY_TRUST_ADMIN |
    win32.POLICY_CREATE_ACCOUNT |
    win32.POLICY_CREATE_SECRET |
    win32.POLICY_CREATE_PRIVILEGE |
    win32.POLICY_SET_DEFAULT_QUOTA_LIMITS |
    win32.POLICY_SET_AUDIT_REQUIREMENTS |
    win32.POLICY_AUDIT_LOG_ADMIN |
    win32.POLICY_SERVER_ADMIN;

const STANDARD_RIGHTS_EXECUTE: i32 = @bitCast(win32.STANDARD_RIGHTS_EXECUTE);
const POLICY_EXECUTE = STANDARD_RIGHTS_EXECUTE |
    win32.POLICY_VIEW_LOCAL_INFORMATION |
    win32.POLICY_LOOKUP_NAMES;

const STANDARD_RIGHTS_REQUIRED: i32 = @bitCast(win32.STANDARD_RIGHTS_REQUIRED);
const POLICY_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED |
    POLICY_READ |
    POLICY_WRITE |
    POLICY_EXECUTE;

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

// See https://msdn.microsoft.com/en-us/library/windows/desktop/ms721859(v=vs.85).aspx#lsa_policy_function_return_values
// and https://msdn.microsoft.com/en-us/library/cc704588.aspx
const NTSTATUS_SUCCESS: i32 = 0x00000000;
const NTSTATUS_ACCESS_DENIED: i32 = 0xC0000022;
const NTSTATUS_INSUFFICIENT_RESOURCES: i32 = 0xC000009A;
const NTSTATUS_INTERNAL_DB_ERROR: i32 = 0xC0000158;
const NTSTATUS_INVALID_HANDLE: i32 = 0xC0000008;
const NTSTATUS_INVALID_SERVER_STATE: i32 = 0xC00000DC;
const NTSTATUS_INVALID_PARAMETER: i32 = 0xC000000D;
const NTSTATUS_NO_SUCH_PRIVILEGE: i32 = 0xC0000060;
const NTSTATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xC0000034;
const NTSTATUS_UNSUCCESSFUL: i32 = 0xC0000001;

const Action = struct {
    const Self = @This();

    const Error = error{
        StringToLong,
        AccountNotFound,
        NoMemory,
        UnableToOpenPolicy,
    };

    privilege: std.AutoHashMap(u32, u32),
    enable: bool,
    allocator: std.mem.Allocator,
    sid: *win32.SID,
    lpAccountName: [:0]u8,
    handle: win32.HANDLE,

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .privilege = std.AutoHashMap(u32, u32).init(allocator),
            .enable = true,
            .allocator = allocator,
            .sid = undefined,
            .lpAccountName = undefined,
            .handle = undefined,
        };
    }

    // https://msdn.microsoft.com/en-us/library/windows/desktop/ms722492(v=vs.85).aspx
    fn UnicodeStringFromString(self: *Self, s: []u8) !win32.UNICODE_STRING {
        const utf16 = try std.unicode.utf8ToUtf16LeAllocZ(self.allocator, s);
        errdefer self.allocator.free(utf16);

        if (utf16.len > 0x7ffe) {
            return Self.Error.StringToLong;
        }
        var len: u16 = @intCast(utf16.len);
        len *= @sizeOf(u16);

        return win32.UNICODE_STRING{
            .Buffer = @ptrCast(utf16),
            .Length = len,
            .MaximumLength = len + @sizeOf(u16),
        };
    }

    fn getPolicyHandle(self: *Self) !void {
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa378299(v=vs.85).aspx
        var objectAttributes: win32.OBJECT_ATTRIBUTES = std.mem.zeroes(win32.OBJECT_ATTRIBUTES);
        const ret = win32.LsaOpenPolicy(
            null,
            &objectAttributes,
            POLICY_ALL_ACCESS,
            @ptrCast(&self.handle),
        );

        if (ret != NTSTATUS_SUCCESS) {
            std.log.err("Failed to open policy handle {d}", .{win32.LsaNtStatusToWinError(ret)});
            return Self.Error.UnableToOpenPolicy;
        }
    }

    fn getAccountNameSid(self: *Self) !*win32.LSA_TRANSLATED_SID2 {
        var names = try self.UnicodeStringFromString(self.lpAccountName);
        var sids: *win32.LSA_TRANSLATED_SID2 = undefined;
        var rd: *win32.LSA_REFERENCED_DOMAIN_LIST = undefined;

        // https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsalookupnames2
        const ret = win32.LsaLookupNames2(
            self.handle,
            win32.LSA_LOOKUP_ISOLATED_AS_LOCAL,
            1,
            &names,
            @ptrCast(&rd),
            @ptrCast(&sids),
        );

        // TODO: assume success?
        _ = win32.LsaFreeMemory(rd);

        if (ret != NTSTATUS_SUCCESS) {
            std.log.err("LsaLookupNames2 error for {s} code {d}", .{ self.lpAccountName, win32.LsaNtStatusToWinError(ret) });
            _ = win32.LsaFreeMemory(sids);
            return Self.Error.AccountNotFound;
        }

        return sids;
    }

    pub fn attemptModifyPrivilege(self: *Self) !void {
        try self.getPolicyHandle();
        std.log.debug("[+] LsaOpenPolicy Success!", .{});

        const sids = try self.getAccountNameSid();
        std.log.debug("[+] getAccountNameSid Success! use: {d}", .{@intFromEnum(sids.*.Use)});

        for (PRIVILEGES, 0..) |privilege, idx| {
            if (self.privilege.count() > 0 and !self.privilege.contains(@truncate(idx))) {
                continue;
            }

            var prefix = "+";

            if (!self.enable) {
                prefix = "-";
            }

            std.log.debug("[{s}] Modifing {s}!", .{ prefix, privilege });

            var ret = NTSTATUS_SUCCESS;
            var priv = try self.UnicodeStringFromString(@constCast(privilege));

            if (self.enable) {
                // https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaaddaccountrights
                ret = win32.LsaAddAccountRights(
                    self.handle,
                    sids.*.Sid,
                    @ptrCast(&priv),
                    1,
                );
            } else {
                // https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaremoveaccountrights
                ret = win32.LsaRemoveAccountRights(
                    self.handle,
                    sids.*.Sid,
                    0,
                    @ptrCast(&priv),
                    1,
                );
            }

            if (ret != NTSTATUS_SUCCESS) {
                std.log.debug("[+] Modify LSA Error ret: {d}", .{win32.LsaNtStatusToWinError(ret)});
            }
        }

        // TODO: assume success?
        _ = win32.LsaFreeMemory(sids);
    }

    pub fn debug(self: *Self) void {
        std.log.info("\nModify Privileges for user\n", .{});
        var itr = self.privilege.keyIterator();

        while (itr.next()) |k| {
            std.log.info("\t{d} == {s}", .{ k.*, PRIVILEGES[k.*] });
        }
        std.log.info("\n", .{});
    }

    pub fn parseUsername(self: *Self, line: [:0]const u8) !void {
        self.lpAccountName = try std.fmt.allocPrintSentinel(self.allocator, "{s}", .{line}, 0);
        errdefer self.allocator.free(self.lpAccountName);
    }

    pub fn parsePrivileges(self: *Self, line: [:0]const u8) !void {
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
        defer self.allocator.free(self.lpAccountName);

        // https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaclose
        const ret = win32.LsaClose(self.handle);
        if (ret != NTSTATUS_SUCCESS) {
            std.log.err("Failed to open policy handle {d} == 0x{x}", .{ ret, ret });
            return;
        }
        std.log.debug("LsaClose Success!", .{});
    }
};

pub fn usage(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: [:0]const u8,
) !void {
    var buffer: []u8 = try std.fmt.allocPrint(allocator,
        \\  This tool exist thanks to https://github.com/petemoore/ntr
        \\
        \\Example:
        \\
        \\ Attempt to enable the privileges SeShutdown & SeTimeZone for the user 'pete':
        \\ .\\{s} pete 18,33
        \\
        \\ Attempt to disable the privileges SeShutdown & SeTimeZone for the user 'pete':
        \\ .\\{s} pete 18,33 -d
        \\
        \\ Show this menu
        \\ .\\{s} -h
        \\
    , .{ argv, argv, argv });

    try std.Io.File.stdout().writeStreamingAll(io, buffer);

    for (PRIVILEGES, 0..) |privilege, idx| {
        buffer = try std.fmt.allocPrint(allocator, "\t{d} = {s}\n", .{ idx, privilege });
        try std.Io.File.stdout().writeStreamingAll(io, buffer);
    }

    std.process.exit(0);
}

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len > 4) {
        try usage(allocator, init.io, args[0]);
    }

    var action = try Action.init(allocator);
    defer action.deinit();

    var i: u8 = 0;

    for (args) |arg| {
        if (std.mem.containsAtLeast(u8, arg, 1, "-h")) {
            try usage(allocator, init.io, args[0]);
        }

        if (std.mem.containsAtLeast(u8, arg, 1, "-disable")) {
            action.enable = false;
        }

        if (i == 1) {
            try action.parseUsername(arg);
        }

        if (i == 2) {
            try action.parsePrivileges(arg);
        }

        i += 1;
    }

    action.debug();

    try action.attemptModifyPrivilege();

    std.log.info("[+] Done", .{});

    std.process.exit(0);
}
