const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Public module that dependents can import as "zig-batchcrypto"
    const batchcrypto_mod = b.addModule("zig-batchcrypto", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Static library artifact (for linking into C or other non-Zig consumers)
    const lib = b.addLibrary(.{
        .name = "zig-batchcrypto",
        .root_module = batchcrypto_mod,
    });
    b.installArtifact(lib);

    // Unit tests -- create a separate module for the test compilation
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const lib_unit_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
