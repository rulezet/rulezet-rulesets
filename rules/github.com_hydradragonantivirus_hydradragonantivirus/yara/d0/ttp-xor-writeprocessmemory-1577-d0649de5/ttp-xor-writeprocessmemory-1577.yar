rule TTP_XOR_WriteProcessMemory_1577 {
  strings:
    $key_1577 = { 42 05 [2] 70 27 [2] 76 12 [2] 58 12 [2] 67 0e }

  condition:
    any of them
}