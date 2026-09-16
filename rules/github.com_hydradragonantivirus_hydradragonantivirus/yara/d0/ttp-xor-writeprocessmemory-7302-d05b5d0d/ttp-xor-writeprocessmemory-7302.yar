rule TTP_XOR_WriteProcessMemory_7302 {
  strings:
    $key_7302 = { 24 70 [2] 16 52 [2] 10 67 [2] 3e 67 [2] 01 7b }

  condition:
    any of them
}