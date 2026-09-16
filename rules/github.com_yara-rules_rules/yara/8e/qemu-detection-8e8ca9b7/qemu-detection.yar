rule Qemu_Detection : AntiVM
{
    meta:
        description = "Looks for Qemu presence"
    strings:
        $a0 = "qemu" nocase wide ascii
    condition:
        any of them
}