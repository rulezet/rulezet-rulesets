rule TTP_XOR_WriteProcessMemory_7581 {
  strings:
    $key_7581 = { 22 f3 [2] 10 d1 [2] 16 e4 [2] 38 e4 [2] 07 f8 }

  condition:
    any of them
}