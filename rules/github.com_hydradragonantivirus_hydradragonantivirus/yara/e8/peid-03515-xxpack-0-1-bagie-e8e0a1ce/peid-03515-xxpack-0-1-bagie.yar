rule PEiD_03515_XXPack_0_1____bagie_ {
  meta:
    description = "[XXPack 0.1 -> bagie]"
    ep_only     = "true"

  strings:
    $a = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 00 68 00 ?? ?? ?? C3 }

  condition:
    $a
}