rule PEiD_00961_kkrunchy_V0_2X____Ryd___Sign_by_fly_ {
  meta:
    description = "[kkrunchy V0.2X -> Ryd ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { BD ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? FF 4D 08 C6 45 0C 05 8D 7D 14 31 C0 B4 04 89 C1 F3 AB BF ?? ?? ?? ?? 57 BE ?? ?? ?? ?? 31 C9 41 FF 4D 0C 8D 9C 8D A0 00 00 00 FF D6 }

  condition:
    $a
}