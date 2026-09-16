rule TTP_XOR_WriteProcessMemory_3a91 {
  strings:
    $key_3a91 = { 6d e3 [2] 5f c1 [2] 59 f4 [2] 77 f4 [2] 48 e8 }

  condition:
    any of them
}