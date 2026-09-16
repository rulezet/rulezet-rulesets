rule PEiD_01401_Obsidium_v1_1_1_1_ {
  meta:
    description = "[Obsidium v1.1.1.1]"
    ep_only     = "true"

  strings:
    $a = { EB 02 ?? ?? E8 E7 1C 00 00 }

  condition:
    $a
}