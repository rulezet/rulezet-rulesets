rule PEiD_02396_Upack_V0_3X____Dwing_ {
  meta:
    description = "[Upack V0.3X -> Dwing]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 09 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 C9 5E 87 0E }

  condition:
    $a
}