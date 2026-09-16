rule PEiD_03546_yzpack_V1_12____UsAr___Sign_by_fly_ {
  meta:
    description = "[yzpack V1.12 -> UsAr ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 ?? ?? ?? ?? B4 09 BA 00 00 1F CD 21 B8 01 4C CD 21 40 00 00 00 50 45 00 00 4C 01 02 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 E0 00 ?? ?? 0B 01 ?? ?? ?? ?? 00 00 }

  condition:
    $a
}