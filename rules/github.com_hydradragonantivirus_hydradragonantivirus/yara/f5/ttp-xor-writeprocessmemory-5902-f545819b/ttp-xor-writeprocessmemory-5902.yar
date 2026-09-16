rule TTP_XOR_WriteProcessMemory_5902 {
  strings:
    $key_5902 = { 0e 70 [2] 3c 52 [2] 3a 67 [2] 14 67 [2] 2b 7b }

  condition:
    any of them
}