rule PEiD_01020_MEW_11_SE_1_0____Northfox_ {
  meta:
    description = "[MEW 11 SE 1.0 -> Northfox]"
    ep_only     = "false"

  strings:
    $a = { E9 ?? ?? ?? ?? 00 00 00 02 00 00 00 0C 00 }

  condition:
    $a
}