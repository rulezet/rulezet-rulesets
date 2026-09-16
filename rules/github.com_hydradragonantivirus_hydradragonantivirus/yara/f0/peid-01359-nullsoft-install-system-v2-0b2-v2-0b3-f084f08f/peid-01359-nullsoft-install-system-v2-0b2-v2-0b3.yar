rule PEiD_01359_Nullsoft_Install_System_v2_0b2__v2_0b3_ {
  meta:
    description = "[Nullsoft Install System v2.0b2, v2.0b3]"
    ep_only     = "true"

  strings:
    $a = { 83 EC 0C 53 55 56 57 FF 15 ?? 70 40 00 8B 35 ?? 92 40 00 05 E8 03 00 00 89 44 24 14 B3 20 FF 15 2C 70 40 00 BF 00 04 00 00 68 ?? ?? ?? 00 57 FF 15 ?? ?? 40 00 57 FF 15 }

  condition:
    $a
}