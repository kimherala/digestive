const std = @import("std");

// Reads any file that doesn't fail to allocate.
pub fn fileRead(allocator: std.mem.Allocator, file_path: []const u8) ![]const u8 {
    const file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_only });
    defer file.close();

    const file_metadata = try file.metadata();

    var file_buffer = try allocator.alloc(u8, file_metadata.size());

    _ = try file.readAll(file_buffer);

    return file_buffer;
}
