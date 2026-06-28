// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const std = @import("std");
const win32 = @import("win32").everything;

const Action = struct {
    const Self = @This();

    const Error = error{
        FailedAllocate,
    };

    command: []u8,
    allocator: std.mem.Allocator,
    io: std.Io,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) !Self {
        return Self{
            .command = "",
            .allocator = allocator,
            .io = io,
        };
    }

    pub fn execute(self: *Self) bool {
        var processInformation: win32.PROCESS_INFORMATION = std.mem.zeroes(win32.PROCESS_INFORMATION);
        var startupInfoExW: win32.STARTUPINFOEXW = std.mem.zeroes(win32.STARTUPINFOEXW);
        var attributeSize: usize = 0;

        // get the required size ... ignore the error return - it's expected to "fail"
        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist
        if (win32.FALSE != win32.InitializeProcThreadAttributeList(
            null,
            1,
            0,
            &attributeSize,
        )) {
            std.log.err("InitializeProcThreadAttributeList GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-getprocessheap
        const hHeap = win32.GetProcessHeap();
        if (hHeap == null) {
            std.log.err("GetProcessHeap GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return false;
        }
        startupInfoExW.StartupInfo.cb = @sizeOf(win32.STARTUPINFOEXW);

        // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc
        startupInfoExW.lpAttributeList = win32.HeapAlloc(
            hHeap,
            win32.HEAP_NONE,
            attributeSize,
        );
        // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree
        defer _ = win32.HeapFree(hHeap, win32.HEAP_NONE, startupInfoExW.lpAttributeList);

        if (startupInfoExW.lpAttributeList == null) {
            std.log.err("startupInfo.lpAttributeList is null GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist
        if (0 == win32.InitializeProcThreadAttributeList(
            startupInfoExW.lpAttributeList,
            1,
            0,
            &attributeSize,
        )) {
            std.log.err("spawnProcessFromPID: InitializeProcThreadAttributeList GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        const hProcess: ?win32.HANDLE = win32.GetCurrentProcess();
        defer CloseHandle(hProcess);

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
        if (0 == win32.UpdateProcThreadAttribute(
            startupInfoExW.lpAttributeList,
            0,
            win32.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            @ptrCast(@constCast(&hProcess)),
            @sizeOf(win32.HANDLE),
            null,
            null,
        )) {
            std.log.err("UpdateProcThreadAttribute GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        const lpApplicationName = std.unicode.utf8ToUtf16LeAllocZ(self.allocator, self.command) catch undefined;
        errdefer self.allocator.free(lpApplicationName);

        const dwCreationFlags = win32.PROCESS_CREATION_FLAGS{
            .EXTENDED_STARTUPINFO_PRESENT = 1,
            .DETACHED_PROCESS = 1,
        };

        std.log.info("[+] Attempting to create {s}\n", .{self.command});

        var lpProcessAttributes: win32.SECURITY_ATTRIBUTES = std.mem.zeroes(win32.SECURITY_ATTRIBUTES);
        lpProcessAttributes.nLength = @sizeOf(win32.SECURITY_ATTRIBUTES);

        var lpThreadAttributes: win32.SECURITY_ATTRIBUTES = std.mem.zeroes(win32.SECURITY_ATTRIBUTES);
        lpThreadAttributes.nLength = @sizeOf(win32.SECURITY_ATTRIBUTES);

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
        if (0 == win32.CreateProcessW(
            null,
            lpApplicationName,
            &lpProcessAttributes,
            &lpThreadAttributes,
            0,
            dwCreationFlags,
            null,
            null,
            @ptrCast(&startupInfoExW),
            &processInformation,
        )) {
            std.log.err("CreateProcessW GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        std.log.info("Process Created - PID: {d} - GLE: {d}", .{ processInformation.dwProcessId, @intFromEnum(win32.GetLastError()) });

        // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
        if (win32.WaitForSingleObject(
            processInformation.hProcess,
            win32.INFINITE,
        ) == win32.WAIT_FAILED) {
            std.log.err("WaitForSingleObject GetLastError: {d}\n", .{@intFromEnum(win32.GetLastError())});
            return false;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-deleteprocthreadattributelist
        win32.DeleteProcThreadAttributeList(
            startupInfoExW.lpAttributeList,
        );

        defer CloseHandle(processInformation.hProcess);
        defer CloseHandle(processInformation.hThread);

        return true;
    }

    pub fn parseCommand(self: *Self, line: [:0]const u8) !void {
        self.command = std.fmt.allocPrint(self.allocator, "{s}", .{line}) catch undefined;
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.command);
    }

    pub fn CloseHandle(handle: ?win32.HANDLE) void {
        if (handle != null and handle.? != win32.INVALID_HANDLE_VALUE) {
            // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
            _ = win32.CloseHandle(handle.?);
        }
    }
};

pub fn usage(allocator: std.mem.Allocator, io: std.Io, argv: [:0]const u8) !void {
    const buffer: []u8 = std.fmt.allocPrint(
        allocator,
        "\\ .\\{s} C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe\x00",
        .{argv},
    ) catch undefined;

    std.Io.File.stdout().writeStreamingAll(io, buffer) catch undefined;

    std.process.exit(0);
}

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexa
    const mutexH: ?win32.HANDLE = win32.CreateMutexA(
        null,
        1,
        "ExecuteWindowsDerp\x00",
    );
    if (mutexH == null or mutexH.? == win32.INVALID_HANDLE_VALUE) {
        std.log.err("Failed to obtain mutex!", .{});
        return;
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
    defer _ = win32.CloseHandle(mutexH.?);

    if (win32.GetLastError() == win32.ERROR_ALREADY_EXISTS) {
        std.log.err("Application already exists!", .{});
        return;
    }

    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len != 2) {
        try usage(
            allocator,
            init.io,
            args[0],
        );
    }

    var action = try Action.init(
        allocator,
        init.io,
    );
    defer action.deinit();

    var i: u8 = 0;

    for (args) |arg| {
        if (i == 1) {
            try action.parseCommand(arg);
        }

        i += 1;
    }

    if (action.command.len <= 0) {
        action.command = std.fmt.allocPrint(action.allocator, "{s}", .{"C:\\windows\\system32\\cmd.exe"}) catch undefined;
    }

    std.log.info("[+] Attempting Execution of: {s}", .{action.command});

    if (!action.execute()) {
        std.log.err("[!] Failed to execute {s}", .{action.command});
        return;
    }

    std.log.info("[+] Executed {s}", .{action.command});

    std.process.exit(0);
}
