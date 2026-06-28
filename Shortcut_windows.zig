const std = @import("std");

pub const UNICODE = true;

const win32 = @import("win32").everything;

const panic = std.debug.FullPanic(std.debug.defaultPanic);

// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const Action = struct {
    const Self = @This();
    source: []u8,
    destination: []u8,
    workingDirectory: []u8,
    arguments: []u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .source = "",
            .destination = "",
            .workingDirectory = "",
            .arguments = "",
            .allocator = allocator,
        };
    }

    pub fn attemptCreateShortcut(self: *Self) !bool {
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/objbase/nf-objbase-coinitialize
            const status = win32.CoInitialize(
                null,
            );
            if (win32.FAILED(status)) {
                std.log.err("CoInitialize FAILED: {d}", .{status});
                return error.Failed;
            }
        }
        // https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-couninitialize
        defer win32.CoUninitialize();

        var ppv: *win32.IShellLinkW = undefined;
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance
            const status = win32.CoCreateInstance(
                win32.CLSID_ShellLink,
                null,
                win32.CLSCTX_INPROC_SERVER,
                win32.IID_IShellLinkW,
                @ptrCast(&ppv),
            );
            if (win32.FAILED(status)) {
                std.log.err("CoCreateInstance FAILED: {d}", .{status});
                return error.Failed;
            }
        }
        // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
        defer _ = win32.IUnknown.Release(@ptrCast(ppv));

        {
            const pszDir = try std.unicode.utf8ToUtf16LeAllocZ(self.allocator, self.workingDirectory);
            defer self.allocator.free(pszDir);

            // https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ishelllinka-setworkingdirectory
            const status = ppv.SetWorkingDirectory(
                pszDir,
            );
            if (win32.FAILED(status)) {
                std.log.err("IShellLinkW_SetWorkingDirectory FAILED: {d}", .{status});
                return error.Failed;
            }
        }

        {
            const pszFile = try std.unicode.utf8ToUtf16LeAllocZ(self.allocator, self.source);
            defer self.allocator.free(pszFile);

            // https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ishelllinka-setpath
            const status = ppv.SetPath(
                pszFile,
            );
            if (win32.FAILED(status)) {
                std.log.err("IShellLinkW_SetPath FAILED: {d}", .{status});
                return error.Failed;
            }
        }

        if (self.arguments.len > 0) {
            {
                const pszArgs = try std.unicode.utf8ToUtf16LeAllocZ(self.allocator, self.arguments);
                defer self.allocator.free(pszArgs);

                // https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ishelllinka-setpath
                const status = ppv.SetArguments(
                    pszArgs,
                );
                if (win32.FAILED(status)) {
                    std.log.err("IShellLinkW_SetPath FAILED: {d}", .{status});
                    return error.Failed;
                }
            }
        }

        // TODO: add https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ishelllinkw-setshowcmd ?

        var ppvObject: *win32.IPersistFile = undefined;
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-queryinterface(refiid_void)
            const status = win32.IUnknown.QueryInterface(
                @ptrCast(ppv),
                win32.IID_IPersistFile,
                @ptrCast(&ppvObject),
            );
            if (win32.FAILED(status)) {
                std.log.err("IUnknown_QueryInterface FAILED: {d}", .{status});
                return error.Failed;
            }
        }
        // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
        defer _ = win32.IUnknown.Release(@ptrCast(ppvObject));

        {
            const destination = try std.unicode.utf8ToUtf16LeAllocZ(self.allocator, self.destination);
            defer self.allocator.free(destination);

            // https://learn.microsoft.com/en-us/windows/win32/api/objidl/nf-objidl-ipersistfile-save
            const status = ppvObject.Save(
                destination,
                1,
            );
            if (win32.FAILED(status)) {
                std.log.err("IPersistFile_Save FAILED: {d}", .{status});
                return error.Failed;
            }
        }

        return true;
    }

    pub fn debug(self: *Self) void {
        std.log.info(
            "\nCreate shortcut :: {s} ==> {s}\n",
            .{ self.source, self.destination },
        );
    }

    pub fn parseSource(self: *Self, line: [:0]const u8) !void {
        self.source = std.fmt.allocPrint(self.allocator, "{s}\x00", .{line}) catch "";
    }

    pub fn parseDestination(self: *Self, line: [:0]const u8) !void {
        self.destination = std.fmt.allocPrint(self.allocator, "{s}\x00", .{line}) catch "";
    }

    pub fn parseWorkingDirectory(self: *Self, line: [:0]const u8) !void {
        self.workingDirectory = std.fmt.allocPrint(self.allocator, "{s}\x00", .{line}) catch "";
    }

    pub fn parseArguments(self: *Self, line: [:0]const u8) !void {
        self.arguments = std.fmt.allocPrint(self.allocator, "{s}\x00", .{line}) catch "";
    }

    pub fn deinit(self: *Self) void {
        if (self.source.len > 0) {
            self.allocator.free(self.source);
        }
        if (self.destination.len > 0) {
            self.allocator.free(self.destination);
        }
        if (self.workingDirectory.len > 0) {
            self.allocator.free(self.workingDirectory);
        }

        if (self.arguments.len > 0) {
            self.allocator.free(self.arguments);
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
        \\  Attempt to create a shortcut at destination which points to source:
        \\
        \\      {s} "source" "destination" "working directory" "arguments"
        \\
        \\  NOTE:
        \\      - Include the '.lnk' extension in your destination.
        \\      - Use absolute paths for source, destination, and working directory
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

        if (i == 2) {
            try action.parseDestination(arg);
        }

        if (i == 3) {
            try action.parseWorkingDirectory(arg);
        }

        if (i == 4) {
            try action.parseArguments(arg);
        }

        i += 1;
    }

    action.debug();

    const success = try action.attemptCreateShortcut();

    if (!success) {
        std.log.info("[!] Failed", .{});
        std.process.exit(1);
    }

    std.log.info("[+] Done", .{});
}
