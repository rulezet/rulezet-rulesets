rule TTP_XOR_WriteProcessMemory_1842 {
  strings:
    $key_1842 = { 4f 30 [2] 7d 12 [2] 7b 27 [2] 55 27 [2] 6a 3b }

  condition:
    any of them
}