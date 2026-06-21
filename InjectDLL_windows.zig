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
    targetPID: u32,
    dll: [:0]u8,

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .allocator = allocator,
            .targetPID = undefined,
            .dll = undefined,
        };
    }

    pub fn inject(self: *Self) !u32 {
        std.log.debug("inject called", .{});

        // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
        const moduleHandle = win32.GetModuleHandleA("kernel32.dll\x00");
        if (moduleHandle == null) {
            std.log.err("[!] Failed GetModuleHandleA :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return Error.UnknownError;
        }
        defer utility.closeHandle(moduleHandle);
        std.log.debug("GetModuleHandleA", .{});

        // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
        const lla = win32.GetProcAddress(moduleHandle, "LoadLibraryA\x00");
        if (lla == null) {
            std.log.err("[!] Failed GetProcAddress :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return Error.UnknownError;
        }

        std.log.debug("GetProcAddress.LoadLibraryA :: {any}", .{lla.?});

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        const processHandle: ?win32.HANDLE = win32.OpenProcess(
            win32.PROCESS_ACCESS_RIGHTS{
                .CREATE_THREAD = 1,
                .QUERY_INFORMATION = 1,
                .VM_OPERATION = 1,
                .VM_WRITE = 1,
                .VM_READ = 1,
            },
            win32.FALSE,
            self.targetPID,
        );

        if (processHandle == null) {
            std.log.err("[!] Failed OpenProcess :: error code ({d})", .{@intFromEnum(win32.GetLastError())});
            return Error.UnknownError;
        }
        defer utility.closeHandle(processHandle);

        std.log.debug("OpenProcess", .{});

        var fullpath: [win32.MAX_PATH]u8 = std.mem.zeroes([win32.MAX_PATH]u8);

        // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfullpathnamea
        const len = win32.GetFullPathNameA(
            self.dll.ptr,
            win32.MAX_PATH,
            @ptrCast(&fullpath),
            null,
        );

        if (len == 0) {
            std.log.err("[!] Error :: GetFullPathNameA({s}) :: {d}", .{ self.dll.ptr, @intFromEnum(win32.GetLastError()) });
            return Error.UnknownError;
        }
        std.log.debug("GetFullPathNameA :: {s} ({d})", .{ fullpath[0 .. len + 1], len });

        // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
        const mem = win32.VirtualAllocEx(
            processHandle,
            null,
            len,
            win32.MEM_COMMIT,
            win32.PAGE_READWRITE,
        );

        if (mem == null) {
            std.log.err("[!] Error :: VirtualAllocEx :: {d}", .{@intFromEnum(win32.GetLastError())});
            return Error.UnknownError;
        }
        std.log.debug("VirtualAllocEx :: {any}", .{mem});
        // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex
        defer _ = win32.VirtualFreeEx(
            processHandle,
            mem,
            0,
            win32.MEM_RELEASE,
        );

        var bytesWritten: usize = 0;

        // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
        if (0 == win32.WriteProcessMemory(
            processHandle,
            mem,
            fullpath[0..].ptr,
            len,
            &bytesWritten,
        )) {
            std.log.err("[!] Error :: WriteProcessMemory :: {d}", .{@intFromEnum(win32.GetLastError())});
            return Error.UnknownError;
        }

        std.log.debug("WriteProcessMemory :: {d}/{d}", .{ bytesWritten, len });

        var thread_id: u32 = 0;

        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex
        const threadHandle = win32.CreateRemoteThreadEx(
            processHandle,
            null,
            0,
            @ptrCast(lla),
            mem,
            0,
            null,
            &thread_id,
        );

        if (threadHandle == null) {
            std.log.err("[!] Error :: CreateRemoteThreadEx :: {d}", .{@intFromEnum(win32.GetLastError())});
            return Error.UnknownError;
        }
        defer utility.closeHandle(threadHandle);

        std.log.debug("CreateRemoteThreadEx", .{});

        // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
        const r = win32.WaitForSingleObject(threadHandle, win32.INFINITE);
        std.log.debug("WaitForSingleObject {d}", .{r});

        var exitcode: u32 = 0;
        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodethread
        if (0 == win32.GetExitCodeThread(threadHandle, &exitcode)) {
            std.log.err("[!] Error :: GetExitCodeThread :: {d}", .{@intFromEnum(win32.GetLastError())});
            return Error.UnknownError;
        }

        std.log.debug("GetExitCodeThread :: {d}", .{exitcode});

        // win32.OutputDebugStringA("RAN THING...");

        return exitcode;
    }

    pub fn debug(self: *Self) void {
        std.log.info("\nAttempt to inject {s} into PID: {d}\n", .{ self.dll, self.targetPID });
    }

    pub fn parseDLL(self: *Self, line: [:0]const u8) !void {
        self.dll = try std.fmt.allocPrintSentinel(self.allocator, "{s}", .{line}, 0);
        errdefer self.allocator.free(self.dll);
    }

    pub fn parsePID(self: *Self, line: [:0]const u8) !void {
        self.targetPID = try std.fmt.parseInt(u32, line, 10);
    }

    pub fn deinit(self: *Self) void {
        defer self.allocator.free(self.dll);
    }
};

pub fn usage(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: [:0]const u8,
) !void {
    const buffer: []u8 = try std.fmt.allocPrint(allocator,
        \\
        \\Example:
        \\
        \\ Attempt to take ownership of PID for the user 'pete':
        \\ .\\{s} PID C:\\windows\\temp\\injectme.dll
        \\
        \\ Show this menu
        \\ .\\{s} -h
        \\
    , .{ argv, argv });

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

    var action = try Action.init(allocator);
    defer action.deinit();

    var i: u8 = 0;

    for (args) |arg| {
        if (i == 1) {
            try action.parsePID(arg);
        }

        if (i == 2) {
            try action.parseDLL(arg);
        }

        i += 1;
    }

    action.debug();

    const exitcode = try action.inject();

    if (exitcode != 0) {
        std.log.info("[+] Success {d}", .{exitcode});
    } else {
        std.log.info("[+] Failure...", .{});
    }

    std.process.exit(1);
}
