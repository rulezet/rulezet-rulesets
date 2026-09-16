rule PEiD_01291_nPack_1_1_250_2006_Beta____NEOx__uinC__ {
  meta:
    description = "[nPack 1.1.250.2006.Beta -> NEOx/[uinC]]"
    ep_only     = "false"

  strings:
    $a = { 83 3D 04 ?? ?? ?? 00 75 05 E9 01 00 00 00 C3 E8 46 00 00 00 E8 73 00 00 00 B8 2E ?? ?? ?? 2B 05 08 ?? ?? ?? A3 00 ?? ?? ?? E8 9C 00 00 00 E8 04 02 00 00 E8 FB 06 00 00 E8 1B 06 00 00 A1 00 ?? ?? ?? C7 05 04 ?? ?? ?? 01 00 00 00 01 05 00 ?? ?? ?? FF 35 00 }

  condition:
    $a
}