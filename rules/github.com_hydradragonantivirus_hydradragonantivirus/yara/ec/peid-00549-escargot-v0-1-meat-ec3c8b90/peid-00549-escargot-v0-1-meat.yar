rule PEiD_00549_Escargot_V0_1______Meat_ {
  meta:
    description = "[Escargot V0.1 -> ++Meat]"
    ep_only     = "true"

  strings:
    $a = { EB 04 40 30 2E 31 60 68 61 }

  condition:
    $a
}