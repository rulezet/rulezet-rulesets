rule PEiD_01093_Microsoft_Visual_C___DLL_ {
  meta:
    description = "[Microsoft Visual C++ DLL]"
    ep_only     = "true"

  strings:
    $a = { 53 55 56 8B 74 24 14 85 F6 57 B8 01 00 00 00 }

  condition:
    $a
}