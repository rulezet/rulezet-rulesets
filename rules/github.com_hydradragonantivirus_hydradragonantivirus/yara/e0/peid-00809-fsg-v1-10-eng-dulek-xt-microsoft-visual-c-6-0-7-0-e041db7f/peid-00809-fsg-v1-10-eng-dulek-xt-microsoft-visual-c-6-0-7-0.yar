rule PEiD_00809_FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0___7_0__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0 / 7.0)]"
    ep_only     = "true"

  strings:
    $a = { 87 FE E8 02 00 00 00 98 CC 5F BB 80 ?? ?? 00 EB 02 CD 20 68 F4 00 00 00 E8 01 00 00 00 E3 }

  condition:
    $a
}