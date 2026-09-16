rule PEiD_00732_Free_Pascal_v1_0_10__win32_GUI__ {
  meta:
    description = "[Free Pascal v1.0.10 (win32 GUI)]"
    ep_only     = "false"

  strings:
    $a = { C6 05 ?? ?? ?? 00 00 E8 ?? ?? 00 00 50 E8 00 00 00 00 FF 25 ?? ?? ?? 00 55 89 E5 }

  condition:
    $a
}