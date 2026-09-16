rule TTP_XOR_WriteProcessMemory_1532 {
  strings:
    $key_1532 = { 42 40 [2] 70 62 [2] 76 57 [2] 58 57 [2] 67 4b }

  condition:
    any of them
}