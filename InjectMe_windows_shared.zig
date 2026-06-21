// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const win32 = @import("win32").everything;
const win32_security = @import("win32").security;
const std = @import("std");

const windows = std.os.windows;

pub export fn DllMain(hinstDLL: win32.HINSTANCE, fdwReason: u32, lpReserved: windows.LPVOID) windows.BOOL {
    _ = lpReserved;
    _ = hinstDLL;
    switch (fdwReason) {
        win32.DLL_PROCESS_ATTACH => {
            _ = win32.MessageBoxA(null, "Injected", "PROCESS ATTACH", .{});
            win32.OutputDebugStringA("InjectMe Process Attach");
        },
        win32.DLL_THREAD_ATTACH => {
            _ = win32.MessageBoxA(null, "Injected", "THREAD ATTACH", .{});
            win32.OutputDebugStringA("InjectMe Thread Attach");
        },
        win32.DLL_THREAD_DETACH => {
            _ = win32.MessageBoxA(null, "Injected", "THREAD DETACH", .{});
            win32.OutputDebugStringA("InjectMe Thread Detach");
        },
        win32.DLL_PROCESS_DETACH => {
            _ = win32.MessageBoxA(null, "Injected", "PROCESS DETACH", .{});
            win32.OutputDebugStringA("InjectMe Process Detach");
        },
        else => {
            _ = win32.MessageBoxA(null, "Injected", "weirdness...", .{});
            win32.OutputDebugStringA("InjectMe wut...");
        },
    }

    return .TRUE;
}
