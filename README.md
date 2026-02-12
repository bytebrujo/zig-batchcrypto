# zig-batchcrypto

Batch Ed25519 signature verification for Zig. Collect signatures, verify them in one call, get per-entry results.

## Why batch verification

When a system needs to verify many Ed25519 signatures (e.g. a block of transactions), verifying them individually leaves performance on the table. Batch verification amortises the cost of expensive elliptic-curve operations across all signatures in the batch.

`zig-batchcrypto` provides the batch collection and verification API now, with sequential per-signature verification under the hood. Future versions will use random linear combination with SIMD-accelerated multi-scalar multiplication for large batches, without any API changes.

## Usage

Add `zig-batchcrypto` as a dependency in your `build.zig`:

```zig
const batchcrypto_dep = b.dependency("zig-batchcrypto", .{
    .target = target,
    .optimize = optimize,
});
my_module.addImport("zig-batchcrypto", batchcrypto_dep.module("zig-batchcrypto"));
```

Then in your source:

```zig
const batchcrypto = @import("zig-batchcrypto");

// Create a verifier with capacity for up to 256 signatures.
var verifier = try batchcrypto.BatchVerifier.init(allocator, 256);
defer verifier.deinit();

// Queue signatures for verification.
try verifier.add(sig_bytes, message, pubkey_bytes);
try verifier.add(sig_bytes2, message2, pubkey_bytes2);

// Verify the entire batch. Returns one result per entry, in order.
const results = verifier.verifyAll();
for (results, 0..) |result, i| {
    switch (result) {
        .valid => {},
        .invalid_signature => std.log.err("bad signature at index {d}", .{i}),
        .invalid_public_key => std.log.err("bad public key at index {d}", .{i}),
    }
}

// Reset and reuse for the next batch.
verifier.reset();
```

## API

### `BatchVerifier`

#### `init(allocator: Allocator, max_batch_size: u32) !BatchVerifier`

Allocate a verifier. `max_batch_size` sets the upper bound on entries per batch. Memory for entries and results is allocated up front.

#### `deinit() void`

Free all allocated memory. The verifier must not be used after this call.

#### `add(sig: [64]u8, msg: []const u8, pubkey: [32]u8) !void`

Queue a signature for verification. `msg` must remain valid until `verifyAll()` returns. Returns `error.BatchFull` if the batch has reached `max_batch_size`.

#### `verifyAll() []const VerifyResult`

Verify every queued entry and return a result slice indexed to match the `add` order. The slice is valid until the next call to `verifyAll()` or `reset()`.

#### `reset() void`

Clear all entries, keeping allocated memory for reuse.

#### `len() u32`

Number of entries currently queued.

### `VerifyResult`

```zig
pub const VerifyResult = enum {
    valid,
    invalid_signature,
    invalid_public_key,
};
```

- `.valid` -- signature and public key are correct for the given message.
- `.invalid_signature` -- public key decoded successfully but the signature does not verify.
- `.invalid_public_key` -- the 32-byte public key is not a valid Ed25519 point encoding.

## Important details

- **Message lifetime**: `add()` stores the message as a slice, not a copy. The caller must keep message memory alive through the `verifyAll()` call.
- **Batch reuse**: after `verifyAll()`, call `reset()` to reuse the same verifier for another batch without reallocating.
- **Capacity**: the `max_batch_size` passed to `init` is a hard cap. Exceeding it returns `error.BatchFull`.
- **Thread safety**: a single `BatchVerifier` instance is not thread-safe. Use one per thread, or synchronise externally.

## Testing

```sh
zig build test
```

The test suite includes unit tests for all API paths (valid, invalid, mixed batches, capacity limits, reset) and the official Ed25519 test vectors from RFC 8032 Section 7.1, which are verified both through `BatchVerifier` and by re-deriving keypairs from seeds to check deterministic signing.

## Building

```sh
zig build          # build static library
zig build test     # run tests
```

Requires Zig 0.13+.
