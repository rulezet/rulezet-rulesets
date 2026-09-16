rule PEiD_00623_EXECryptor_2_x____SoftComplete_Developement_ {
  meta:
    description = "[EXECryptor 2.x -> SoftComplete Developement]"
    ep_only     = "false"

  strings:
    $a = { A4 ?? ?? 00 00 00 00 00 FF FF FF FF 3C ?? ?? 00 94 ?? ?? 00 D8 ?? ?? 00 00 00 00 00 FF FF FF FF }

  condition:
    $a
}