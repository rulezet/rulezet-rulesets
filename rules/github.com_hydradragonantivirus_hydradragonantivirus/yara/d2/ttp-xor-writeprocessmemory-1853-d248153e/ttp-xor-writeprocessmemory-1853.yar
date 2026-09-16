rule TTP_XOR_WriteProcessMemory_1853 {
  strings:
    $key_1853 = { 4f 21 [2] 7d 03 [2] 7b 36 [2] 55 36 [2] 6a 2a }

  condition:
    any of them
}