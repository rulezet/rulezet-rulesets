rule TTP_XOR_WriteProcessMemory_1549 {
  strings:
    $key_1549 = { 42 3b [2] 70 19 [2] 76 2c [2] 58 2c [2] 67 30 }

  condition:
    any of them
}