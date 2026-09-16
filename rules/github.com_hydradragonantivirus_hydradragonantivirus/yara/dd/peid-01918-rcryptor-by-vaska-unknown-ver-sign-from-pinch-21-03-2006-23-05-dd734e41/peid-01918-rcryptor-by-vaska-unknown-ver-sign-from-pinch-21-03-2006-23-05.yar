rule PEiD_01918_RCryptor_by_Vaska_unknown_ver__sign_from_pinch_21_03_2006_23_05__ {
  meta:
    description = "[RCryptor by Vaska unknown ver (sign from pinch 21.03.2006 23:05)]"
    ep_only     = "true"

  strings:
    $a = { 90 58 90 50 90 8B 00 90 3C 50 90 58 0F 85 67 D6 EF 11 50 68 00 10 14 13 B8 00 10 14 13 3D 00 64 14 13 74 06 80 30 BC 40 EB F3 E8 00 00 00 00 C3 }

  condition:
    $a
}