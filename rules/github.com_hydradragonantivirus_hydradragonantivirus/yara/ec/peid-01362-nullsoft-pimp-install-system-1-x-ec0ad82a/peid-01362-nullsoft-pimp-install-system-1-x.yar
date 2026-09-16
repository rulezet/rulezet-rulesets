rule PEiD_01362_Nullsoft_PiMP_Install_System_1_x_ {
  meta:
    description = "[Nullsoft PiMP Install System 1.x]"
    ep_only     = "false"

  strings:
    $a = { 83 EC 0C 53 56 57 FF 15 ?? ?? 40 00 05 E8 03 00 00 BE ?? ?? ?? 00 89 44 24 10 B3 20 FF 15 28 ?? 40 00 68 00 04 00 00 FF 15 ?? ?? 40 00 50 56 FF 15 ?? ?? 40 00 80 3D ?? ?? ?? 00 22 75 08 80 C3 02 BE ?? ?? ?? 00 8A 06 8B 3D ?? ?? 40 00 84 C0 74 ?? 3A C3 74 }

  condition:
    $a
}