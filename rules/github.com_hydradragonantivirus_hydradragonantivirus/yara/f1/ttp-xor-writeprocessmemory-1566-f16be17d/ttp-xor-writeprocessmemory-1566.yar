rule TTP_XOR_WriteProcessMemory_1566 {
  strings:
    $key_1566 = { 42 14 [2] 70 36 [2] 76 03 [2] 58 03 [2] 67 1f }

  condition:
    any of them
}