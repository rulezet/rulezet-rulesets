rule PEiD_02141_Special_EXE_Pasword_Protector_1_01__Eng_____Pavol_Cerven_ {
  meta:
    description = "[Special EXE Pasword Protector 1.01 (Eng) -> Pavol Cerven]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E 77 00 00 8D 95 C6 77 00 00 8D 8D FF 77 00 00 55 68 00 20 00 00 51 52 6A 00 FF 95 04 7A 00 00 5D 6A 00 FF 95 FC 79 00 00 8D 8D 60 78 00 00 8D 95 85 01 00 00 55 68 00 }

  condition:
    $a
}