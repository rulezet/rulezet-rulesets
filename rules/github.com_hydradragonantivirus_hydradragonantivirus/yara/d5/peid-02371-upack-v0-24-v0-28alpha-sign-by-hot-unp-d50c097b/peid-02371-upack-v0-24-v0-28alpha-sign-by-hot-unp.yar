rule PEiD_02371_Upack_v0_24___v0_28alpha____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack v0.24 ~ v0.28alpha -> Sign by hot_UNP]"
    ep_only     = "true"

  strings:
    $a = { BE 88 01 40 00 AD ?? ?? 95 AD 91 F3 A5 AD }

  condition:
    $a
}