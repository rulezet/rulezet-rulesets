rule PEiD_00789_FSG_v1_10__Eng_____dulek_xt_____Borland_Delphi___Borland_C____ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi / Borland C++)]"
    ep_only     = "true"

  strings:
    $a = { 2B C2 E8 02 00 00 00 95 4A 59 8D 3D 52 F1 2A E8 C1 C8 1C BE 2E ?? ?? 18 EB 02 AB A0 03 F7 }

  condition:
    $a
}