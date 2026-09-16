rule TTP_XOR_WriteProcessMemory_1552 {
  strings:
    $key_1552 = { 42 20 [2] 70 02 [2] 76 37 [2] 58 37 [2] 67 2b }

  condition:
    any of them
}