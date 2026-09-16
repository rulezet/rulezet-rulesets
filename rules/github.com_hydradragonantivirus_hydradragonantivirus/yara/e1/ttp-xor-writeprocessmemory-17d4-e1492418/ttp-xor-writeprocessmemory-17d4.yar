rule TTP_XOR_WriteProcessMemory_17d4 {
  strings:
    $key_17d4 = { 40 a6 [2] 72 84 [2] 74 b1 [2] 5a b1 [2] 65 ad }

  condition:
    any of them
}