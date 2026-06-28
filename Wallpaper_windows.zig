const std = @import("std");

const win32 = @import("win32").everything;

// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const Action = struct {
    const Self = @This();
    source: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .source = "",
            .allocator = allocator,
        };
    }

    pub fn attemptSetWallpaper(self: *Self) !bool {
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/objbase/nf-objbase-coinitialize
            const status = win32.CoInitialize(
                null, //    [in, optional] LPVOID pvReserved
            );
            if (win32.FAILED(status)) {
                std.log.err("CoInitialize FAILED: {d}", .{status});
                return error.Failed;
            }
        }
        // https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-couninitialize
        defer win32.CoUninitialize();

        var ppv: *win32.IDesktopWallpaper = undefined;
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance
            const status = win32.CoCreateInstance(
                win32.CLSID_DesktopWallpaper, //       [in]  REFCLSID  rclsid
                null, //                            [in]  LPUNKNOWN pUnkOuter
                win32.CLSCTX_ALL, //             [in]  DWORD     dwClsContext
                win32.IID_IDesktopWallpaper, //          [in]  REFIID    riid
                @ptrCast(&ppv), //                        [out] LPVOID    *ppv
            );
            if (win32.FAILED(status)) {
                std.log.err("CoCreateInstance FAILED: {d}", .{status});
                return error.Failed;
            }
        }
        // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
        defer _ = win32.IUnknown.Release(@ptrCast(ppv));

        {
            const wallpaper = try std.unicode.utf8ToUtf16LeAllocZ(self.allocator, self.source);
            defer self.allocator.free(wallpaper);

            // https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-idesktopwallpaper-setwallpaper
            const status = ppv.SetWallpaper(@ptrFromInt(0), wallpaper);

            if (win32.FAILED(status)) {
                std.log.err("IDesktopWallpaper_SetWallpaper FAILED: {d}", .{status});
                return error.Failed;
            }
        }

        return true;
    }

    pub fn debug(self: *Self) void {
        std.log.info(
            "\nSet wallpaper :: {s}\n",
            .{self.source},
        );
    }

    pub fn parseSource(self: *Self, line: [:0]const u8) !void {
        self.source = std.fmt.allocPrint(self.allocator, "{s}\x00", .{line}) catch "";
    }

    pub fn deinit(self: *Self) void {
        if (self.source.len > 0) {
            self.allocator.free(self.source);
        }
    }
};

pub fn usage(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: [:0]const u8,
) !void {
    const buffer: []u8 = try std.fmt.allocPrint(allocator,
        \\
        \\Usage:
        \\
        \\  Attempt to set the desktop wallpaper:
        \\
        \\      {s} "path to the wallpaper file"
        \\
        \\  NOTE:
        \\      - Use absolute paths...
        \\
        \\  Show this menu:
        \\
        \\      {s} -h
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

    if (args.len < 2) {
        try usage(allocator, init.io, args[0]);
    }

    var action = try Action.init(allocator);
    defer action.deinit();

    var i: u8 = 0;

    for (args) |arg| {
        if (std.mem.containsAtLeast(u8, arg, 1, "-h") or std.mem.containsAtLeast(u8, arg, 1, "-H")) {
            try usage(allocator, init.io, args[0]);
            std.process.exit(0);
        }

        if (i == 1) {
            try action.parseSource(arg);
        }

        i += 1;
    }

    action.debug();

    const success = try action.attemptSetWallpaper();

    if (!success) {
        std.log.info("[!] Failed", .{});
        std.process.exit(1);
    }

    std.log.info("[+] Done", .{});
}
