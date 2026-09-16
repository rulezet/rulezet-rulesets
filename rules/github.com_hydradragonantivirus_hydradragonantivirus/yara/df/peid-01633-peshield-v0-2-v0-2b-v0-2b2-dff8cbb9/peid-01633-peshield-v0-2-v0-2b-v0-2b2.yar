rule PEiD_01633_PESHiELD_v0_2___v0_2b___v0_2b2_ {
  meta:
    description = "[PESHiELD v0.2 / v0.2b / v0.2b2]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 ?? ?? ?? ?? 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }

  condition:
    $a
}