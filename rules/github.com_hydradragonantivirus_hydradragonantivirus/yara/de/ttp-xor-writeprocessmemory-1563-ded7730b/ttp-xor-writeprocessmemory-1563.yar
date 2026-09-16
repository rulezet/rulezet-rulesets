rule TTP_XOR_WriteProcessMemory_1563 {
  strings:
    $key_1563 = { 42 11 [2] 70 33 [2] 76 06 [2] 58 06 [2] 67 1a }

  condition:
    any of them
}