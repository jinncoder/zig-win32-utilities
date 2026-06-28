// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

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

    allocator: std.mem.Allocator,
    targetPID: u32,
    lpOutFile: [:0]u8,

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .allocator = allocator,
            .targetPID = undefined,
            .lpOutFile = undefined,
        };
    }

    pub fn dump(self: *Self) void {
        utility.miniDumpPID(self.allocator, self.targetPID, self.lpOutFile) catch |err| {
            std.log.err("[!] Failed to dump {d} to {s} - {any}", .{ self.targetPID, self.lpOutFile, err });
        };
    }

    pub fn debug(self: *Self) void {
        std.log.info("\nRelabel Targets PID: {d}\n", .{self.targetPID});
        std.log.info("\n", .{});
    }

    pub fn parseOutfile(self: *Self, line: [:0]const u8) !void {
        self.lpOutFile = try std.fmt.allocPrintSentinel(self.allocator, "{s}", .{line}, 0);
        errdefer self.allocator.free(self.lpOutFile);
    }

    pub fn parsePID(self: *Self, line: [:0]const u8) !void {
        self.targetPID = try std.fmt.parseInt(u32, line, 10);
    }

    pub fn deinit(self: *Self) void {
        defer self.allocator.free(self.lpOutFile);
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
        \\ Attempt to enable the privileges SeDebug and then dump a process by PID
        \\ .\\{s} 764 C:\lol.dmp
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

    if (args.len != 3) {
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
            try action.parseOutfile(arg);
        }

        i += 1;
    }

    action.dump();

    std.log.info("[+] Done", .{});

    std.process.exit(0);
}
