rule PEiD_00601_EXECryptor_2_0_2_1____www_strongbit_com_ {
  meta:
    description = "[EXECryptor 2.0/2.1 -> www.strongbit.com]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 F4 56 57 53 BE ?? ?? ?? ?? B8 00 00 ?? ?? 89 45 FC 89 C2 8B 46 0C 09 C0 0F 84 ?? 00 00 00 01 D0 89 C3 50 FF 15 94 ?? ?? ?? 09 C0 0F 85 0F 00 00 00 53 FF 15 98 ?? ?? ?? 09 C0 0F 84 ?? 00 00 00 89 45 F8 6A 00 8F 45 F4 8B 06 09 C0 8B 55 FC 0F }

  condition:
    $a
}