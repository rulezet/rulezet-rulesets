rule PEiD_00811_FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0___7_0__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0 / 7.0)]"
    ep_only     = "true"

  strings:
    $a = { F7 D8 40 49 EB 02 E0 0A 8D 35 80 ?? ?? ?? 0F B6 C2 EB 01 9C 8D 1D F4 00 00 00 EB 01 3C 80 }

  condition:
    $a
}