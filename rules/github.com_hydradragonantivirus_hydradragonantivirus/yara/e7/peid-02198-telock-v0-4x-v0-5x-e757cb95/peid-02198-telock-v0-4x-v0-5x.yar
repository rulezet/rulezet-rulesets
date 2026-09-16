rule PEiD_02198_tElock_v0_4x___v0_5x_ {
  meta:
    description = "[tElock v0.4x - v0.5x]"
    ep_only     = "true"

  strings:
    $a = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 ?? 8B FE 68 79 01 ?? ?? 59 EB 01 }

  condition:
    $a
}