rule PEiD_02384_Upack_V0_36____Dwing_ {
  meta:
    description = "[Upack V0.36 -> Dwing]"
    ep_only     = "true"

  strings:
    $a = { BE ?? ?? ?? ?? FF 36 E9 C3 00 00 00 }

  condition:
    $a
}