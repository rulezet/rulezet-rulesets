rule TTP_XOR_WriteProcessMemory_7a91 {
  strings:
    $key_7a91 = { 2d e3 [2] 1f c1 [2] 19 f4 [2] 37 f4 [2] 08 e8 }

  condition:
    any of them
}