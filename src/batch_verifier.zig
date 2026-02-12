const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const Ed25519 = crypto.sign.Ed25519;
const Sha512 = crypto.hash.sha2.Sha512;
const Curve = Ed25519.Curve;

pub const VerifyResult = enum {
    valid,
    invalid_signature,
    invalid_public_key,
};

pub const Entry = struct {
    sig: [64]u8,
    msg: []const u8,
    pubkey: [32]u8,
};

pub const BatchVerifier = struct {
    entries: std.ArrayListUnmanaged(Entry),
    results: []VerifyResult,
    allocator: Allocator,
    max_batch_size: u32,

    pub fn init(allocator: Allocator, max_batch_size: u32) !BatchVerifier {
        var entries = std.ArrayListUnmanaged(Entry){};
        try entries.ensureTotalCapacity(allocator, max_batch_size);

        const results = try allocator.alloc(VerifyResult, max_batch_size);
        @memset(results, .valid);

        return .{
            .entries = entries,
            .results = results,
            .allocator = allocator,
            .max_batch_size = max_batch_size,
        };
    }

    pub fn deinit(self: *BatchVerifier) void {
        self.entries.deinit(self.allocator);
        self.allocator.free(self.results);
        self.* = undefined;
    }

    pub fn add(self: *BatchVerifier, sig: [64]u8, msg: []const u8, pubkey: [32]u8) !void {
        if (self.entries.items.len >= self.max_batch_size) {
            return error.BatchFull;
        }
        try self.entries.append(self.allocator, .{
            .sig = sig,
            .msg = msg,
            .pubkey = pubkey,
        });
    }

    /// Verify all entries in the batch. Returns a slice of results corresponding
    /// to each entry added via `add`. The returned slice is valid until the next
    /// call to `verifyAll` or `reset`.
    pub fn verifyAll(self: *BatchVerifier) []const VerifyResult {
        const count = self.entries.items.len;
        if (count == 0) return self.results[0..0];

        // For v0.1: sequential verification of each entry.
        // TODO: For batches >= 4, implement random-linear-combination batch
        // verification using Edwards25519.mulMulti for a significant speedup.
        for (self.entries.items, 0..) |entry, i| {
            self.results[i] = verifySingle(entry);
        }

        return self.results[0..count];
    }

    pub fn reset(self: *BatchVerifier) void {
        self.entries.clearRetainingCapacity();
    }

    /// The number of entries currently queued for verification.
    pub fn len(self: *const BatchVerifier) u32 {
        return @intCast(self.entries.items.len);
    }

    fn verifySingle(entry: Entry) VerifyResult {
        const sig = Ed25519.Signature.fromBytes(entry.sig);

        // Validate public key encoding
        const pubkey = Ed25519.PublicKey.fromBytes(entry.pubkey) catch {
            return .invalid_public_key;
        };

        // Verify signature
        sig.verify(entry.msg, pubkey) catch {
            return .invalid_signature;
        };

        return .valid;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "empty batch returns empty slice" {
    var bv = try BatchVerifier.init(std.testing.allocator, 64);
    defer bv.deinit();

    const results = bv.verifyAll();
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "single valid signature" {
    var bv = try BatchVerifier.init(std.testing.allocator, 64);
    defer bv.deinit();

    const kp = Ed25519.KeyPair.generate();
    const msg = "hello batch crypto";
    const sig = try kp.sign(msg, null);

    try bv.add(sig.toBytes(), msg, kp.public_key.toBytes());
    const results = bv.verifyAll();

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expectEqual(VerifyResult.valid, results[0]);
}

test "single invalid signature" {
    var bv = try BatchVerifier.init(std.testing.allocator, 64);
    defer bv.deinit();

    const kp = Ed25519.KeyPair.generate();
    const msg = "hello batch crypto";
    var sig = (try kp.sign(msg, null)).toBytes();
    sig[0] ^= 0xff; // corrupt signature

    try bv.add(sig, msg, kp.public_key.toBytes());
    const results = bv.verifyAll();

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0] != .valid);
}

test "invalid public key" {
    var bv = try BatchVerifier.init(std.testing.allocator, 64);
    defer bv.deinit();

    const kp = Ed25519.KeyPair.generate();
    const msg = "test message";
    const sig = try kp.sign(msg, null);

    // Use a known small-order point as an invalid public key
    const bad_pubkey = [_]u8{0} ** 32;
    try bv.add(sig.toBytes(), msg, bad_pubkey);
    const results = bv.verifyAll();

    try std.testing.expectEqual(@as(usize, 1), results.len);
    try std.testing.expect(results[0] != .valid);
}

test "mixed valid and invalid" {
    var bv = try BatchVerifier.init(std.testing.allocator, 64);
    defer bv.deinit();

    const kp1 = Ed25519.KeyPair.generate();
    const kp2 = Ed25519.KeyPair.generate();
    const msg1 = "message one";
    const msg2 = "message two";

    const sig1 = try kp1.sign(msg1, null);
    const sig2 = try kp2.sign(msg2, null);

    // Entry 0: valid
    try bv.add(sig1.toBytes(), msg1, kp1.public_key.toBytes());
    // Entry 1: wrong message (invalid signature)
    try bv.add(sig2.toBytes(), "wrong message", kp2.public_key.toBytes());
    // Entry 2: valid
    try bv.add(sig2.toBytes(), msg2, kp2.public_key.toBytes());

    const results = bv.verifyAll();

    try std.testing.expectEqual(@as(usize, 3), results.len);
    try std.testing.expectEqual(VerifyResult.valid, results[0]);
    try std.testing.expectEqual(VerifyResult.invalid_signature, results[1]);
    try std.testing.expectEqual(VerifyResult.valid, results[2]);
}

test "reset clears entries" {
    var bv = try BatchVerifier.init(std.testing.allocator, 64);
    defer bv.deinit();

    const kp = Ed25519.KeyPair.generate();
    const msg = "reset test";
    const sig = try kp.sign(msg, null);

    try bv.add(sig.toBytes(), msg, kp.public_key.toBytes());
    try std.testing.expectEqual(@as(u32, 1), bv.len());

    bv.reset();
    try std.testing.expectEqual(@as(u32, 0), bv.len());

    const results = bv.verifyAll();
    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "batch full returns error" {
    var bv = try BatchVerifier.init(std.testing.allocator, 2);
    defer bv.deinit();

    const kp = Ed25519.KeyPair.generate();
    const msg = "test";
    const sig = try kp.sign(msg, null);
    const sig_bytes = sig.toBytes();
    const pk_bytes = kp.public_key.toBytes();

    try bv.add(sig_bytes, msg, pk_bytes);
    try bv.add(sig_bytes, msg, pk_bytes);
    try std.testing.expectError(error.BatchFull, bv.add(sig_bytes, msg, pk_bytes));
}

test "multiple valid signatures" {
    var bv = try BatchVerifier.init(std.testing.allocator, 64);
    defer bv.deinit();

    // Pre-allocate messages so pointers remain valid through verifyAll.
    var msgs: [10][32]u8 = undefined;
    for (&msgs, 0..) |*msg, i| {
        @memset(msg, @intCast(i));
    }

    for (&msgs) |*msg| {
        const kp = Ed25519.KeyPair.generate();
        const sig = try kp.sign(msg, null);
        try bv.add(sig.toBytes(), msg, kp.public_key.toBytes());
    }

    const results = bv.verifyAll();
    try std.testing.expectEqual(@as(usize, 10), results.len);
    for (results) |r| {
        try std.testing.expectEqual(VerifyResult.valid, r);
    }
}

// ---------------------------------------------------------------------------
// RFC 8032 Ed25519 cross-validation
// ---------------------------------------------------------------------------

fn hexToBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(100_000);
    var result: [hex.len / 2]u8 = undefined;
    for (&result, 0..) |*byte, i| {
        byte.* = std.fmt.parseInt(u8, hex[2 * i .. 2 * i + 2], 16) catch unreachable;
    }
    return result;
}

test "rfc 8032 ed25519 test vectors" {
    // Official test vectors from RFC 8032 Section 7.1, verified independently
    // with Python's cryptography library.
    const Vector = struct {
        seed: [32]u8,
        pubkey: [32]u8,
        msg: []const u8,
        sig: [64]u8,
    };

    const vectors = [_]Vector{
        // Test 1: empty message
        .{
            .seed = comptime hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
            .pubkey = comptime hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            .msg = "",
            .sig = comptime hexToBytes("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        },
        // Test 2: single byte message (0x72)
        .{
            .seed = comptime hexToBytes("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"),
            .pubkey = comptime hexToBytes("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"),
            .msg = &comptime hexToBytes("72"),
            .sig = comptime hexToBytes("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        },
        // Test 3: two byte message (0xaf82)
        .{
            .seed = comptime hexToBytes("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"),
            .pubkey = comptime hexToBytes("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"),
            .msg = &comptime hexToBytes("af82"),
            .sig = comptime hexToBytes("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
        },
    };

    // Part A: Verify all RFC 8032 signatures through BatchVerifier
    var bv = try BatchVerifier.init(std.testing.allocator, 8);
    defer bv.deinit();

    for (vectors) |v| {
        try bv.add(v.sig, v.msg, v.pubkey);
    }
    const results = bv.verifyAll();
    try std.testing.expectEqual(vectors.len, results.len);
    for (results) |r| {
        try std.testing.expectEqual(VerifyResult.valid, r);
    }

    // Part B: Re-derive keypair from seed and check deterministic signing
    for (vectors) |v| {
        const kp = try Ed25519.KeyPair.generateDeterministic(v.seed);
        // Public key derived from seed must match the RFC vector
        try std.testing.expectEqualSlices(u8, &v.pubkey, &kp.public_key.toBytes());
        // Signature must match (Ed25519 signing is deterministic)
        const sig = try kp.sign(v.msg, null);
        try std.testing.expectEqualSlices(u8, &v.sig, &sig.toBytes());
    }
}
