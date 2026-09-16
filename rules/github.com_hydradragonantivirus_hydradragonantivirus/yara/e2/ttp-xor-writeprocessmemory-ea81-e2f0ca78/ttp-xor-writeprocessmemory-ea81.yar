rule TTP_XOR_WriteProcessMemory_ea81 {
  strings:
    $key_ea81 = { bd f3 [2] 8f d1 [2] 89 e4 [2] a7 e4 [2] 98 f8 }

  condition:
    any of them
}