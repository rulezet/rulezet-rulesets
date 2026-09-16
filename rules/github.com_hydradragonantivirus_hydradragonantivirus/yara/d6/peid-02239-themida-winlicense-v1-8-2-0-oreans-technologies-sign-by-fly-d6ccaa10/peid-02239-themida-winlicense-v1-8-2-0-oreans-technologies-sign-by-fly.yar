rule PEiD_02239_Themida_WinLicense_V1_8_2_0______Oreans_Technologies___Sign_by_fly_ {
  meta:
    description = "[Themida/WinLicense V1.8.2.0 + -> Oreans Technologies ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D ?? ?? ?? ?? FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 }

  condition:
    $a
}