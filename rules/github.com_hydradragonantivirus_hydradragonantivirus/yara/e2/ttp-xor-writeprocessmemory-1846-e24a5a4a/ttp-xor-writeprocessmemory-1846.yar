rule TTP_XOR_WriteProcessMemory_1846 {
  strings:
    $key_1846 = { 4f 34 [2] 7d 16 [2] 7b 23 [2] 55 23 [2] 6a 3f }

  condition:
    any of them
}