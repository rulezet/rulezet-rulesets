rule TTP_XOR_WriteProcessMemory_17d1 {
  strings:
    $key_17d1 = { 40 a3 [2] 72 81 [2] 74 b4 [2] 5a b4 [2] 65 a8 }

  condition:
    any of them
}