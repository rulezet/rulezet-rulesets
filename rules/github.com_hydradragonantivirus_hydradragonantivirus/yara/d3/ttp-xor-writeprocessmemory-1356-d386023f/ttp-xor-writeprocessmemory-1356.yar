rule TTP_XOR_WriteProcessMemory_1356 {
  strings:
    $key_1356 = { 44 24 [2] 76 06 [2] 70 33 [2] 5e 33 [2] 61 2f }

  condition:
    any of them
}