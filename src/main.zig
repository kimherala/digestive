const std = @import("std");

// Manual (-h, --help)
const manual = @embedFile("manual.txt");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer {
        const deinit_status = gpa.deinit();
        if (deinit_status == .leak) std.testing.expect(false) catch @panic("MEMORY LEAKED!");
    }

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len == 2) {
        if (std.mem.eql(u8, args[1][0..], "-h")) {
            try stdout.print("{s}\n", .{manual});
        } else {
            const sha = fileHashAsHex(allocator, args[1]) catch |err| {
                std.log.info("{}", .{err});
                try stdout.print("{s}\n", .{"0"});
                return;
            };
            defer allocator.free(sha);
            try stdout.print("{s}\n", .{sha});
        }
    }
}

// Reads any file that doesn't fail to allocate.
pub fn fileRead(allocator: std.mem.Allocator, file_path: []const u8) ![]const u8 {
    const file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_only });
    defer file.close();

    const file_metadata = try file.metadata();

    var file_buffer = try allocator.alloc(u8, file_metadata.size());

    _ = try file.readAll(file_buffer);

    return file_buffer;
}

/// Returns file SHA3-512 hash as hex.
pub fn fileHashAsHex(allocator: std.mem.Allocator, file_path: []const u8) ![]const u8 {
    const file = try fileRead(allocator, file_path);
    defer allocator.free(file);

    var hash: [64]u8 = undefined;
    var sha3_512 = std.crypto.hash.sha3.Sha3_512.init(.{});

    sha3_512.update(file);
    sha3_512.final(&hash);

    const hex = std.fmt.bytesToHex(hash, .lower);

    var result = try allocator.dupe(u8, &hex);
    return result;
}
