rule PEiD_01115_Microsoft_Visual_C___v7_0_ {
  meta:
    description = "[Microsoft Visual C++ v7.0]"
    ep_only     = "true"

  strings:
    $a = { 6A 0C 68 88 BF 01 10 E8 B8 1C 00 00 33 C0 40 89 45 E4 8B 75 0C 33 FF 3B F7 75 0C 39 3D 6C 1E 12 10 0F 84 B3 00 00 00 89 7D FC 3B F0 74 05 83 FE 02 75 31 A1 98 36 12 10 3B C7 74 0C FF 75 10 56 }

  condition:
    $a
}