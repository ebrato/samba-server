const std = @import("std");

const TargetSpec = struct {
    const CpuModelOverride = enum {
        arm1176jzf_s,
        cortex_a7,
    };

    step_name: []const u8,
    out_name: []const u8,
    triple: []const u8,
    c_flags: []const []const u8,
    cpu_model: ?CpuModelOverride = null,
    windows: bool = false,
};

fn resolveQuery(
    b: *std.Build,
    triple: []const u8,
    cpu_model: ?TargetSpec.CpuModelOverride,
) std.Build.ResolvedTarget {
    var q = std.Target.Query.parse(.{ .arch_os_abi = triple }) catch |err| {
        std.debug.panic("invalid target triple '{s}': {s}", .{ triple, @errorName(err) });
    };
    if (cpu_model) |cpu| {
        q.cpu_model = switch (cpu) {
            .arm1176jzf_s => .{ .explicit = &std.Target.arm.cpu.arm1176jzf_s },
            .cortex_a7 => .{ .explicit = &std.Target.arm.cpu.cortex_a7 },
        };
    }
    return b.resolveTargetQuery(q);
}

fn addSmbExe(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    name: []const u8,
    c_flags: []const []const u8,
    is_windows: bool,
) *std.Build.Step.Compile {
    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = true,
    });
    mod.addCSourceFile(.{
        .file = b.path("smb.cpp"),
        .flags = c_flags,
        .language = .cpp,
    });

    const exe = b.addExecutable(.{
        .name = name,
        .root_module = mod,
    });

    if (is_windows) {
        exe.linkSystemLibrary("ws2_32");
    }

    return exe;
}

pub fn build(b: *std.Build) void {
    // Keep all installed artifacts in ./release instead of ./zig-out.
    b.resolveInstallPrefix("release", .{});

    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Optimization mode (default: ReleaseFast)",
    ) orelse .ReleaseFast;
    const keep_pdb = optimize == .Debug;

    const default_triple = b.option(
        []const u8,
        "default-triple",
        "Default triple for `zig build` and `zig build native`",
    ) orelse "x86_64-linux-musl";
    const default_target = resolveQuery(b, default_triple, null);

    const base_flags_posix: []const []const u8 = &.{
        "-std=c++17",
        "-pthread",
        "-DSMB_ENABLE_CONTRACTS=1",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Wconversion",
        "-Wsign-conversion",
        "-Wshadow",
    };

    const base_flags_windows: []const []const u8 = &.{
        "-std=c++17",
        "-DSMB_ENABLE_CONTRACTS=1",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Wconversion",
        "-Wsign-conversion",
        "-Wshadow",
    };

    // Fast local build (default selected target).
    const native_is_windows = default_target.result.os.tag == .windows;
    const native_flags = if (native_is_windows) base_flags_windows else base_flags_posix;
    const native_exe = addSmbExe(b, default_target, optimize, "smb_cli", native_flags, native_is_windows);
    const native_install = b.addInstallArtifact(native_exe, .{
        .pdb_dir = if (keep_pdb) .default else .disabled,
    });
    const native_step = b.step("native", "Build smb_cli for the selected/host target");
    native_step.dependOn(&native_install.step);

    // Cross-build matrix.
    const matrix_step = b.step("matrix", "Build the full cross-platform/cross-arch matrix");

    // Cosmopolitan build via cosmoc++.
    const cosmo_out = b.getInstallPath(.bin, "smb_cli_x86_64-unknown-cosmo.com");
    const mkdir_release_bin = b.addSystemCommand(&.{ "mkdir", "-p", b.exe_dir });
    const cosmo_cmd = b.addSystemCommand(&.{
        "cosmoc++",
        "-O2",
        "-std=c++17",
        "-pthread",
        "-DSMB_ENABLE_CONTRACTS=1",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Wconversion",
        "-Wsign-conversion",
        "-Wshadow",
        "-o",
        cosmo_out,
        "smb.cpp",
    });
    cosmo_cmd.step.dependOn(&mkdir_release_bin.step);
    const cosmo_step = b.step("cosmo", "Build x86_64-unknown-cosmo with cosmoc++");
    if (optimize == .Debug) {
        cosmo_step.dependOn(&cosmo_cmd.step);
    } else {
        const cosmo_dbg = b.fmt("{s}.dbg", .{cosmo_out});
        const rm_cosmo_dbg = b.addSystemCommand(&.{ "rm", "-f", cosmo_dbg });
        rm_cosmo_dbg.step.dependOn(&cosmo_cmd.step);
        cosmo_step.dependOn(&rm_cosmo_dbg.step);
    }

    const specs = [_]TargetSpec{
        .{ .step_name = "linux-x86_64", .out_name = "smb_cli_linux_x86_64", .triple = "x86_64-linux-musl", .c_flags = base_flags_posix },
        .{ .step_name = "linux-x86", .out_name = "smb_cli_linux_x86", .triple = "x86-linux-musl", .c_flags = base_flags_posix },
        .{ .step_name = "linux-armv6", .out_name = "smb_cli_linux_armv6", .triple = "arm-linux-musleabihf", .c_flags = base_flags_posix, .cpu_model = .arm1176jzf_s },
        .{ .step_name = "linux-armv7", .out_name = "smb_cli_linux_armv7", .triple = "arm-linux-musleabihf", .c_flags = base_flags_posix, .cpu_model = .cortex_a7 },
        .{ .step_name = "linux-armv8", .out_name = "smb_cli_linux_arm64", .triple = "aarch64-linux-musl", .c_flags = base_flags_posix },
        .{ .step_name = "linux-riscv64", .out_name = "smb_cli_linux_riscv64", .triple = "riscv64-linux-musl", .c_flags = base_flags_posix },
        .{ .step_name = "linux-mips", .out_name = "smb_cli_linux_mips", .triple = "mips-linux-musleabi", .c_flags = base_flags_posix },
        .{ .step_name = "linux-mipsel", .out_name = "smb_cli_linux_mipsel", .triple = "mipsel-linux-musleabi", .c_flags = base_flags_posix },
        .{ .step_name = "linux-mips-hf", .out_name = "smb_cli_linux_mips_hf", .triple = "mips-linux-musleabihf", .c_flags = base_flags_posix },
        .{ .step_name = "linux-mipsel-hf", .out_name = "smb_cli_linux_mipsel_hf", .triple = "mipsel-linux-musleabihf", .c_flags = base_flags_posix },
        .{ .step_name = "linux-mips64", .out_name = "smb_cli_linux_mips64", .triple = "mips64-linux-muslabi64", .c_flags = base_flags_posix },
        .{ .step_name = "linux-mips64el", .out_name = "smb_cli_linux_mips64el", .triple = "mips64el-linux-muslabi64", .c_flags = base_flags_posix },
        .{ .step_name = "linux-mips64n32", .out_name = "smb_cli_linux_mips64n32", .triple = "mips64-linux-muslabin32", .c_flags = base_flags_posix },
        .{ .step_name = "linux-mips64eln32", .out_name = "smb_cli_linux_mips64eln32", .triple = "mips64el-linux-muslabin32", .c_flags = base_flags_posix },
        .{ .step_name = "macos-x86_64", .out_name = "smb_cli_macos_x86_64", .triple = "x86_64-macos", .c_flags = base_flags_posix },
        .{ .step_name = "macos-arm64", .out_name = "smb_cli_macos_arm64", .triple = "aarch64-macos", .c_flags = base_flags_posix },
        .{ .step_name = "windows-x86", .out_name = "smb_cli_windows_x86.exe", .triple = "x86-windows-gnu", .c_flags = base_flags_windows, .windows = true },
        .{ .step_name = "windows-amd64", .out_name = "smb_cli_windows_amd64.exe", .triple = "x86_64-windows-gnu", .c_flags = base_flags_windows, .windows = true },
        .{ .step_name = "windows-arm64", .out_name = "smb_cli_windows_arm64.exe", .triple = "aarch64-windows-gnu", .c_flags = base_flags_windows, .windows = true },
        .{ .step_name = "freebsd-x86_64", .out_name = "smb_cli_freebsd_x86_64", .triple = "x86_64-freebsd", .c_flags = base_flags_posix },
        .{ .step_name = "freebsd-arm64", .out_name = "smb_cli_freebsd_arm64", .triple = "aarch64-freebsd", .c_flags = base_flags_posix },
    };

    inline for (specs) |spec| {
        const resolved = resolveQuery(b, spec.triple, spec.cpu_model);
        const exe = addSmbExe(b, resolved, optimize, spec.step_name, spec.c_flags, spec.windows);
        const install_artifact = b.addInstallArtifact(exe, .{
            .dest_sub_path = spec.out_name,
            .pdb_dir = if (keep_pdb) .default else .disabled,
        });

        const per_target_step = b.step(spec.step_name, b.fmt("Build target {s}", .{spec.triple}));
        per_target_step.dependOn(&install_artifact.step);
        matrix_step.dependOn(&install_artifact.step);
    }

    // Keep default `zig build` fast/local.
    b.default_step = native_step;
}
