rule TTP_XOR_WriteProcessMemory_17d2 {
  strings:
    $key_17d2 = { 40 a0 [2] 72 82 [2] 74 b7 [2] 5a b7 [2] 65 ab }

  condition:
    any of them
}