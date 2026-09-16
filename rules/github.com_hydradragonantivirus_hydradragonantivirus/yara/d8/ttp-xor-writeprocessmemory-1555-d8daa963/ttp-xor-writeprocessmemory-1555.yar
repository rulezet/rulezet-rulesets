rule TTP_XOR_WriteProcessMemory_1555 {
  strings:
    $key_1555 = { 42 27 [2] 70 05 [2] 76 30 [2] 58 30 [2] 67 2c }

  condition:
    any of them
}