const std = @import("std");
const ioutil = @import("ioutil.zig");

const HashHint = enum {
    sha256,
    sha512,
    sha3_512,
    blake2,
    blake3,
};

/// Returns file SHA3-512 hash as hex.
pub fn fileHash(allocator: std.mem.Allocator, file_path: []const u8, comptime hash_hint: HashHint) ![]const u8 {
    const file = try ioutil.fileRead(allocator, file_path);
    defer allocator.free(file);

    const hash = switch (hash_hint) {
        .sha256 => blk: {
            var digest: [32]u8 = undefined;
            const hashFunc = std.crypto.hash.sha2.Sha256;
            hashFunc.hash(file, &digest, .{});
            break :blk digest;
        },
        .sha512 => blk: {
            var digest: [64]u8 = undefined;
            const hashFunc = std.crypto.hash.sha2.Sha512;
            hashFunc.hash(file, &digest, .{});
            break :blk digest;
        },
        .sha3_512 => blk: {
            var digest: [64]u8 = undefined;
            const hashFunc = std.crypto.hash.sha3.Sha3_512;
            hashFunc.hash(file, &digest, .{});
            break :blk digest;
        },
        .blake2 => blk: {
            var digest: [64]u8 = undefined;
            const hashFunc = std.crypto.hash.blake2.Blake2b512;
            hashFunc.hash(file, &digest, .{});
            break :blk digest;
        },
        .blake3 => blk: {
            var digest: [32]u8 = undefined;
            const hashFunc = std.crypto.hash.Blake3;
            hashFunc.hash(file, &digest, .{});
            break :blk digest;
        },
    };

    const hex = std.fmt.bytesToHex(hash, .lower);

    var result = try allocator.dupe(u8, &hex);
    return result;
}
