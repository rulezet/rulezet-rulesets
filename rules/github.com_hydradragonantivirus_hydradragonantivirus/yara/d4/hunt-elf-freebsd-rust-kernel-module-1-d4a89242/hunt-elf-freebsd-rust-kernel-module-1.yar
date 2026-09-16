rule HUNT_ELF_FREEBSD_RUST_KERNEL_MODULE_1 {
  meta:
    author      = "@qutluch@infosec.exchange"
    description = "Rule to surface FreeBSD kernel modules built with Rust."
    reference   = "https://research.nccgroup.com/2022/08/31/writing-freebsd-kernel-modules-in-rust/"
    DaysofYARA  = "29/100"
    license     = "BSD-2-Clause"
    date        = "2024-01-31"
    version     = "1.0"

  strings:
            $rust1 = "/rustc/"
    $rust2 = "/library/core/src/"
    $rust3 = "/library/std/src/"
    $rust4 = "/rust/deps"
    $f1    = "module_register_init"

  condition:
    uint32(0) == 0x464c457f
    and uint16(0x7) == 0x9
    and (#rust1 + #rust2 + #rust3 + #rust4) > 15
    and $f1
}