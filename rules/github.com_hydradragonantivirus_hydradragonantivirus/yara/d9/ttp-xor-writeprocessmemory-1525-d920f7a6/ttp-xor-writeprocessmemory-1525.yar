rule TTP_XOR_WriteProcessMemory_1525 {
  strings:
    $key_1525 = { 42 57 [2] 70 75 [2] 76 40 [2] 58 40 [2] 67 5c }

  condition:
    any of them
}