const std = @import("std");
const builtin = @import("builtin");

const targets: []const std.Target.Query = &.{
    .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .gnu },
    .{ .cpu_arch = .x86_64, .os_tag = .windows, .abi = .msvc },
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .gnu },
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
};

pub fn package(b: *std.Build, exe: *std.Build.Step.Compile, t: std.Target.Query) !void {
    const target_output = b.addInstallArtifact(exe, .{
        .dest_dir = .{
            .override = .{
                .custom = try t.zigTriple(b.allocator),
            },
        },
    });

    b.getInstallStep().dependOn(&target_output.step);
}

pub fn build(b: *std.Build) !void {
    const sources = [_][]const u8{
        "AddUser_windows_shared.zig",
        "BackupOperatorToDomainAdministrator_windows.zig",
        //        "Execute_windows.zig",
        //        "HighToSystem_windows.zig",
        //        "HighToTrustedInstaller_windows.zig",
        //        "InjectDLL_windows.zig",
        //        "InjectMe_windows_shared.zig",
        //        "Minidump_windows.zig",
        //        "ModifyPrivilege_windows.zig",
        //        "NTRights_windows.zig",
        //        "PasswordFilter_windows_shared.zig",
        //        "ReflectDLL_windows.zig",
        //        "RelabelAbuse_windows.zig",
        //        "ServiceAddUser_windows.zig",
        //        "SessionExec_windows.zig",
        //        "shellcode_windows.zig",
        //        "RemoteShellcode_windows_shared.zig",
        //        "Shortcut_windows.zig",
        //        "Wallpaper_windows.zig",

        //        "shellcode_linux.zig",
    };

    const optimize = b.standardOptimizeOption(.{});

    const zigwin32 = b.createModule(.{
        .root_source_file = b.path("zigwin32/win32.zig"),
    });

    var gpa = std.heap.DebugAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    for (targets) |t| {
        for (sources) |source| {
            var file: ?[]const u8 = "";

            if (std.mem.containsAtLeast(u8, source, 1, "_windows")) {
                if (t.os_tag != .windows) continue;
                var parts = std.mem.tokenizeSequence(u8, source, "_windows");
                file = parts.next();
            }

            if (std.mem.containsAtLeast(u8, source, 1, "_linux")) {
                if (t.os_tag != .linux) continue;
                var parts = std.mem.tokenizeSequence(u8, source, "_linux");
                file = parts.next();
            }

            var mode: ?[]const u8 = "release";
            const cpu_arch: ?[]const u8 = "x86_64";
            const abi: ?[]const u8 = switch (t.abi.?) {
                .msvc => "MSVC",
                .gnu => "GNU",
                .musl => "MUSL",
                else => "UNKNOWN",
            };

            if (optimize == std.builtin.OptimizeMode.Debug) {
                mode = "debug";
            }

            file = std.fmt.allocPrint(allocator, "{s}-{s}-{s}-{s}", .{ file.?, abi.?, cpu_arch.?, mode.? }) catch undefined;

            const resolved_target = b.resolveTargetQuery(.{
                .abi = t.abi,
                .cpu_arch = t.cpu_arch,
                .os_tag = t.os_tag,
            });

            if (std.mem.containsAtLeast(u8, source, 1, "_shared")) {
                const dll = b.addLibrary(.{
                    .name = file.?,
                    .linkage = .dynamic,
                    .root_module = b.createModule(.{
                        .root_source_file = b.path(source),
                        .target = resolved_target,
                        .optimize = optimize,
                    }),
                });

                if (t.os_tag == .windows) {
                    dll.subsystem = .Console;
                    dll.root_module.addImport("win32", zigwin32);
                }

                try package(b, dll, t);
            } else {
                const exe = b.addExecutable(.{
                    .name = file.?,
                    .root_module = b.createModule(.{
                        .root_source_file = b.path(source),
                        .target = resolved_target,
                        .optimize = optimize,
                    }),
                });

                if (t.os_tag == .windows) {
                    exe.subsystem = .Console;
                    exe.root_module.addImport("win32", zigwin32);
                }

                try package(b, exe, t);
            }

            allocator.free(file.?);
        }
    }
}

comptime {
    const current_zig = builtin.zig_version;
    const min_zig = std.SemanticVersion.parse("0.16.0") catch unreachable;
    if (current_zig.order(min_zig) == .lt) {
        const error_message =
            \\Sorry, it looks like your version of zig is too old. :-(
            \\
            \\This project requires zig {}
            \\
            \\Please download a build from
            \\
            \\https://ziglang.org/download/
            \\
        ;
        @compileError(std.fmt.comptimePrint(error_message, .{min_zig}));
    }
}
