rule PEiD_00786_FSG_v1_10__Eng_____dulek_xt_____Borland_C___1999__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Borland C++ 1999)]"
    ep_only     = "true"

  strings:
    $a = { EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9 }

  condition:
    $a
}