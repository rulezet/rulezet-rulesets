rule TTP_XOR_WriteProcessMemory_1543 {
  strings:
    $key_1543 = { 42 31 [2] 70 13 [2] 76 26 [2] 58 26 [2] 67 3a }

  condition:
    any of them
}