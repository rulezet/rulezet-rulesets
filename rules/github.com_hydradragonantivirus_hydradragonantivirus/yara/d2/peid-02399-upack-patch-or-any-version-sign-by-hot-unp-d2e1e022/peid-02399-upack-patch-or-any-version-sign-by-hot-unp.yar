rule PEiD_02399_Upack_Patch_or_any_Version____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack_Patch or any Version -> Sign by hot_UNP]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 09 00 00 00 ?? ?? ?? 00 E9 06 02 }

  condition:
    $a
}