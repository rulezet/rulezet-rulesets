rule TTP_XOR_WriteProcessMemory_1530 {
  strings:
    $key_1530 = { 42 42 [2] 70 60 [2] 76 55 [2] 58 55 [2] 67 49 }

  condition:
    any of them
}