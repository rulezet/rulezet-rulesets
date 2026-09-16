rule PEiD_01126_Microsoft_Visual_C___ {
  meta:
    description = "[Microsoft Visual C++]"
    ep_only     = "true"

  strings:
    $a = { 8B 44 24 08 56 83 E8 ?? 74 ?? 48 75 }

  condition:
    $a
}