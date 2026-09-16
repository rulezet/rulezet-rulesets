rule PEiD_03357_VProtector_V1_0__Build_2004_12_13_ {
  meta:
    description = "[VProtector V1.0 [Build 2004.12.13]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 1A 89 40 00 68 56 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

  condition:
    $a
}