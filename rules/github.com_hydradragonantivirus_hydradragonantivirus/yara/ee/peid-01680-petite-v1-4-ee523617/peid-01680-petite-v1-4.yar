rule PEiD_01680_Petite_v1_4_ {
  meta:
    description = "[Petite v1.4]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? ?? ?? 66 9C 60 50 8B D8 03 00 68 ?? ?? ?? ?? 6A 00 }

  condition:
    $a
}