rule PEiD_03538_yoda_s_Protector_v1_03_2_by_Ashkbiz_Danehkar_ {
  meta:
    description = "[yoda's Protector v1.03.2 by Ashkbiz Danehkar]"
    ep_only     = "false"

  strings:
    $a = { E8 03 00 00 00 EB 01 ?? BB 55 00 00 00 E8 03 00 00 00 EB 01 ?? E8 8F 00 00 00 E8 03 00 00 00 EB 01 ?? E8 82 00 00 00 E8 03 00 00 00 EB 01 ?? E8 B8 00 00 00 E8 03 00 00 00 EB 01 ?? E8 AB 00 00 00 E8 03 00 00 00 EB 01 ?? 83 FB 55 E8 03 00 00 00 EB 01 ?? 75 2E E8 03 00 00 00 EB 01 ?? C3 60 E8 00 00 00 00 5D 81 ED 94 73 42 00 8B D5 81 C2 E3 73 42 00 52 E8 01 00 00 00 C3 C3 E8 03 00 00 }

  condition:
    $a
}