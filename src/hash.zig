const std = @import("std");
const ioutil = @import("ioutil.zig");

/// Returns file SHA3-512 hash as hex.
pub fn fileHash(allocator: std.mem.Allocator, file_path: []const u8) ![]const u8 {
    const file = try ioutil.fileRead(allocator, file_path);
    defer allocator.free(file);

    var hash: [64]u8 = undefined;
    var sha3_512 = std.crypto.hash.sha3.Sha3_512.init(.{});

    sha3_512.update(file);
    sha3_512.final(&hash);

    const hex = std.fmt.bytesToHex(hash, .lower);

    var result = try allocator.dupe(u8, &hex);
    return result;
}
