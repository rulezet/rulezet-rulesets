rule PEiD_02251_Thinstall_Embedded_V1_9X____Jitit___Sign_by_fly_ {
  meta:
    description = "[Thinstall Embedded V1.9X -> Jitit ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 ?? ?? ?? ?? 50 E8 87 FC FF FF 59 59 A1 ?? ?? ?? ?? 8B 40 10 03 05 ?? ?? ?? ?? 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 }

  condition:
    $a
}