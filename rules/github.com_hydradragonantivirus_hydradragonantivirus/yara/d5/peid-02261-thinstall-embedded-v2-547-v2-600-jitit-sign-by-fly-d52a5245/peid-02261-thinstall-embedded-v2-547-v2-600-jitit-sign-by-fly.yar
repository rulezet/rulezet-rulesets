rule PEiD_02261_Thinstall_Embedded_V2_547_V2_600____Jitit___Sign_by_fly_ {
  meta:
    description = "[Thinstall Embedded V2.547-V2.600 -> Jitit ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 00 00 58 BB BC 18 00 00 2B C3 50 68 ?? ?? ?? ?? 68 60 1B 00 00 68 60 00 00 00 E8 35 FF FF FF E9 99 FF FF FF 00 00 }

  condition:
    $a
}