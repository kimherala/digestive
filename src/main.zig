const std = @import("std");
const hash = @import("hash.zig");

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
            const sha = hash.fileHash(allocator, args[1], .sha256) catch |err| {
                std.log.info("{}", .{err});
                try stdout.print("{s}\n", .{"0"});
                return;
            };
            defer allocator.free(sha);
            try stdout.print("{s}\n", .{sha});
        }
    }
}
