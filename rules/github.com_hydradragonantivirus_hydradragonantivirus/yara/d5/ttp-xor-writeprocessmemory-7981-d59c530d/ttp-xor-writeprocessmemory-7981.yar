rule TTP_XOR_WriteProcessMemory_7981 {
  strings:
    $key_7981 = { 2e f3 [2] 1c d1 [2] 1a e4 [2] 34 e4 [2] 0b f8 }

  condition:
    any of them
}