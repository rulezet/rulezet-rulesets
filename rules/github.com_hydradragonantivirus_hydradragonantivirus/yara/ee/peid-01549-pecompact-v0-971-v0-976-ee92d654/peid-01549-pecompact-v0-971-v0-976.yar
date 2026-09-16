rule PEiD_01549_PECompact_v0_971___v0_976_ {
  meta:
    description = "[PECompact v0.971 - v0.976]"
    ep_only     = "true"

  strings:
    $a = { EB 06 68 C3 9C 60 E8 5D 55 5B 81 ED 8B 85 01 85 66 C7 85 }

  condition:
    $a
}