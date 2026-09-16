rule TTP_XOR_WriteProcessMemory_1d66 {
  strings:
    $key_1d66 = { 4a 14 [2] 78 36 [2] 7e 03 [2] 50 03 [2] 6f 1f }

  condition:
    any of them
}