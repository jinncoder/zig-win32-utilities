const std = @import("std");

pub const UNICODE = true;

const win32 = struct {
    usingnamespace @import("win32").system.com;
    usingnamespace @import("win32").zig;
    usingnamespace @import("win32").ui.shell;
};

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
                null, //    [in, optional] LPVOID pvReserved
            );
            if (win32.FAILED(status)) {
                std.log.err("CoInitialize FAILED: {d}", .{status});
                return error.Failed;
            }
        }
        // https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-couninitialize
        defer win32.CoUninitialize();

        var ppv: *win32.IShellLink = undefined;
        {
            // https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance
            const status = win32.CoCreateInstance(
                win32.CLSID_ShellLink, //       [in]  REFCLSID  rclsid
                null, //                        [in]  LPUNKNOWN pUnkOuter
                win32.CLSCTX_INPROC_SERVER, //  [in]  DWORD     dwClsContext
                win32.IID_IShellLinkW, //       [in]  REFIID    riid
                @ptrCast(&ppv), //              [out] LPVOID    *ppv
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
                pszDir, // [in] LPCSTR pszDir
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
                pszFile, // [in] LPCSTR pszFile
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
                    pszArgs, // [in] LPCWSTR pszArgs
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
                win32.IID_IPersistFile, //  [in] REFIID riid,
                @ptrCast(&ppvObject), //    [in] void   **ppvObject
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
                destination, // [in] LPCOLESTR pszFileName,
                1, //           [in] BOOL      fRemember
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

    pub fn parseSource(self: *Self, line: []u8) !void {
        self.source = std.fmt.allocPrintSentinel(self.allocator, "{s}", .{line}, 0) catch "";
    }

    pub fn parseDestination(self: *Self, line: []u8) !void {
        self.destination = std.fmt.allocPrintSentinel(self.allocator, "{s}", .{line}, 0) catch "";
    }

    pub fn parseWorkingDirectory(self: *Self, line: []u8) !void {
        self.workingDirectory = std.fmt.allocPrintSentinel(self.allocator, "{s}", .{line}, 0) catch "";
    }

    pub fn parseArguments(self: *Self, line: []u8) !void {
        self.arguments = std.fmt.allocPrintSentinel(self.allocator, "{s}", .{line}, 0) catch "";
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.source);
        self.allocator.free(self.destination);
        self.allocator.free(self.workingDirectory);
        self.allocator.free(self.arguments);
    }
};

pub fn usage(argv: []u8) !void {
    const stdout = std.io.getStdOut().writer();

    try stdout.print(
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

    std.posix.exit(0);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    // Parse args into string array (error union needs 'try')
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
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
        std.posix.exit(1);
    }

    std.log.info("[+] Done", .{});
}
