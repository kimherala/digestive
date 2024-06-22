const std = @import("std");
const ioutil = @import("ioutil.zig");

pub const EncodingHint = enum {
    raw,
    hex,
    base64,
};

pub const HashHint = enum {
    sha256,
    sha512,
    sha3_512,
    blake2,
    blake3,
};

pub fn fileHash(allocator: std.mem.Allocator, filePath: []const u8, hashHint: HashHint, encoding: EncodingHint) ![]u8 {
    const file = try ioutil.fileRead(allocator, filePath);
    defer allocator.free(file);

    const digest = try digestBytes(allocator, hashHint, file);
    defer allocator.free(digest);
    const result = try encodeBytes(allocator, encoding, digest);

    return result;
}

fn digestBytes(allocator: std.mem.Allocator, hashHint: HashHint, input: []const u8) ![]u8 {
    switch (hashHint) {
        .sha256 => {
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(input, &digest, .{});
            return try allocator.dupe(u8, &digest);
        },
        .sha512 => {
            var digest: [64]u8 = undefined;
            std.crypto.hash.sha2.Sha512.hash(input, &digest, .{});
            return try allocator.dupe(u8, &digest);
        },
        .sha3_512 => {
            var digest: [64]u8 = undefined;
            std.crypto.hash.sha3.Sha3_512.hash(input, &digest, .{});
            return try allocator.dupe(u8, &digest);
        },
        .blake2 => {
            var digest: [64]u8 = undefined;
            std.crypto.hash.blake2.Blake2b512.hash(input, &digest, .{});
            return try allocator.dupe(u8, &digest);
        },
        .blake3 => {
            var digest: [32]u8 = undefined;
            std.crypto.hash.Blake3.hash(input, &digest, .{});
            return try allocator.dupe(u8, &digest);
        },
    }
}

pub fn encodeBytes(allocator: std.mem.Allocator, encoding: EncodingHint, input: []const u8) ![]u8 {
    switch (encoding) {
        .raw => {
            const result: []u8 = try allocator.alloc(u8, input.len);
            std.mem.copyForwards(u8, result, input);
            return result;
        },
        .hex => {
            const result = try bytesToHex(allocator, input, .lower);
            return result;
        },
        .base64 => {
            const base64Encoder = std.base64.Base64Encoder.init(std.base64.standard_alphabet_chars, '=');
            const result = try allocator.alloc(u8, base64Encoder.calcSize(input.len));
            _ = base64Encoder.encode(result, input);
            return result;
        },
    }
}

// Modified version of std.fmt.bytesToHex.
// The standard library version requires the input size to be known at compile time.
pub fn bytesToHex(allocator: std.mem.Allocator, input: []const u8, case: std.fmt.Case) ![]u8 {
    if (input.len == 0) return &[_]u8{};

    const charset = "0123456789" ++ if (case == .upper) "ABCDEF" else "abcdef";
    var result: []u8 = try allocator.alloc(u8, input.len * 2);

    for (input, 0..) |b, i| {
        result[i * 2 + 0] = charset[b >> 4];
        result[i * 2 + 1] = charset[b & 15];
    }

    return result;
}

pub fn hashHintFromString(functionString: []const u8) !HashHint {
    if (std.mem.eql(u8, functionString, "sha256")) {
        return .sha256;
    }
    if (std.mem.eql(u8, functionString, "sha512")) {
        return .sha512;
    }
    if (std.mem.eql(u8, functionString, "sha3-512")) {
        return .sha3_512;
    }
    if (std.mem.eql(u8, functionString, "blake2")) {
        return .blake2;
    }
    if (std.mem.eql(u8, functionString, "blake3")) {
        return .blake3;
    }

    return error.HashHintNotFound;
}

pub fn encodingHintFromString(encodingString: []const u8) !EncodingHint {
    if (std.mem.eql(u8, encodingString, "raw")) {
        return .raw;
    }
    if (std.mem.eql(u8, encodingString, "hex")) {
        return .hex;
    }
    if (std.mem.eql(u8, encodingString, "base64")) {
        return .base64;
    }

    return error.EncodingHintNotFound;
}

test "bytesToHex" {
    const allocator = std.testing.allocator;
    const data = "test";

    var standard = std.fmt.bytesToHex(data, .lower);
    const testData = try bytesToHex(allocator, data, .lower);
    defer allocator.free(testData);

    try std.testing.expectEqualSlices(u8, &standard, testData);
}
