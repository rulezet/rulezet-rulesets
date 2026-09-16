rule PEiD_02009_RLPack_V1_18_Basic_Edition__aPLib_or_LZMA_____ap0x_ {
  meta:
    description = "[RLPack V1.18 Basic Edition (aPLib or LZMA) -> ap0x]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 ?? ?? 00 00 8D 9D ?? 02 00 00 33 FF E8 ?? 01 00 00 }

  condition:
    $a
}