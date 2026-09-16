rule TTP_XOR_WriteProcessMemory_6381 {
  strings:
    $key_6381 = { 34 f3 [2] 06 d1 [2] 00 e4 [2] 2e e4 [2] 11 f8 }

  condition:
    any of them
}