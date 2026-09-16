rule PEiD_03525_yoda_s_Protector_1_02___1_03____Ashkbiz_Danehkar_ {
  meta:
    description = "[yoda's Protector 1.02 - 1.03 -> Ashkbiz Danehkar]"
    ep_only     = "true"

  strings:
    $a = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 }

  condition:
    $a
}