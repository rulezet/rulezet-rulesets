rule PEiD_02010_RLPack_V1_18_Basic_Edition__LZMA_4_30_____ap0x_ {
  meta:
    description = "[RLPack V1.18 Basic Edition (LZMA 4.30) -> ap0x]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 8B 2C 24 83 C4 04 8D B5 21 0B 00 00 8D 9D FF 02 00 00 33 FF E8 9F 01 00 00 6A 40 68 00 }

  condition:
    $a
}