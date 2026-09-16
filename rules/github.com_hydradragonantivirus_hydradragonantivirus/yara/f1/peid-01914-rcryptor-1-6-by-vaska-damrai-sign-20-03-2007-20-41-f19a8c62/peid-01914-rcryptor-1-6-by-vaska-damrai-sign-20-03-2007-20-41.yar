rule PEiD_01914_RCryptor_1_6_by_Vaska__Damrai_sign_20_03_2007_20_41__ {
  meta:
    description = "[RCryptor 1.6 by Vaska (Damrai sign 20.03.2007 20:41)]"
    ep_only     = "true"

  strings:
    $a = { 33 D0 68 40 A1 14 13 FF D2 B8 00 10 14 13 3D 24 C0 14 13 74 06 80 30 BB 40 EB F3 33 C0 C3 }

  condition:
    $a
}