rule PEiD_01077_Microsoft_Visual_C___7_0_ {
  meta:
    description = "[Microsoft Visual C++ 7.0]"
    ep_only     = "true"

  strings:
    $a = { 6A 0C 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 C0 40 89 45 E4 8B 75 0C }

  condition:
    $a
}