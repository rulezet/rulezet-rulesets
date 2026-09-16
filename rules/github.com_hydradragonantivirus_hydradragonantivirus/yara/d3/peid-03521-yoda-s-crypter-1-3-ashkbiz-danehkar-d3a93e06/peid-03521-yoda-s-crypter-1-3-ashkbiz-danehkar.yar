rule PEiD_03521_yoda_s_Crypter_1_3____Ashkbiz_Danehkar_ {
  meta:
    description = "[yoda's Crypter 1.3 -> Ashkbiz Danehkar]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00 81 E9 C6 28 40 00 8B D5 81 C2 C6 28 40 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }

  condition:
    $a
}