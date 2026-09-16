rule PEiD_00580_EXE_Stealth_v2_71_ {
  meta:
    description = "[EXE Stealth v2.71]"
    ep_only     = "true"

  strings:
    $a = { EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED B0 27 40 }

  condition:
    $a
}