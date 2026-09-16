rule PEiD_00864_Goats_Mutilator_v1_6____Goat__e0f_ {
  meta:
    description = "[Goats Mutilator v1.6 -> Goat/_e0f]"
    ep_only     = "true"

  strings:
    $a = { E8 EA 0B 00 00 ?? ?? ?? 8B 1C 79 F6 63 D8 8D 22 B0 BF F6 49 08 C3 02 BD 3B 6C 29 46 13 28 5D }

  condition:
    $a
}