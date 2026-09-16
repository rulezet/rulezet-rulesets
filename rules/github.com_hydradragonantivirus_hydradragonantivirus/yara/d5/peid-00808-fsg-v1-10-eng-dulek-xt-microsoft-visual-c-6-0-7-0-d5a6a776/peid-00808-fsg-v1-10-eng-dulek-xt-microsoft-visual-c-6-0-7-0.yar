rule PEiD_00808_FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0___7_0__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0 / 7.0)]"
    ep_only     = "true"

  strings:
    $a = { 0B D0 8B DA E8 02 00 00 00 40 A0 5A EB 01 9D B8 80 ?? ?? ?? EB 02 CD 20 03 D3 8D 35 F4 00 }

  condition:
    $a
}