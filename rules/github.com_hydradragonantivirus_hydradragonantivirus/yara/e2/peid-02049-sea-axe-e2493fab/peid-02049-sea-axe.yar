rule PEiD_02049_SEA_AXE_ {
  meta:
    description = "[SEA-AXE]"
    ep_only     = "true"

  strings:
    $a = { FC BC ?? ?? 0E 1F E8 ?? ?? 26 A1 ?? ?? 8B 1E ?? ?? 2B C3 8E C0 B1 ?? D3 E3 }

  condition:
    $a
}