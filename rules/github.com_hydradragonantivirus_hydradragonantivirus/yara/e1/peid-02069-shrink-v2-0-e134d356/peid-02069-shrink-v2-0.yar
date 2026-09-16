rule PEiD_02069_Shrink_v2_0_ {
  meta:
    description = "[Shrink v2.0]"
    ep_only     = "true"

  strings:
    $a = { E9 ?? ?? 50 9C FC BE ?? ?? 8B FE 8C C8 05 ?? ?? 8E C0 06 57 B9 }

  condition:
    $a
}