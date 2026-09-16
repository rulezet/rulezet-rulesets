rule TTP_XOR_WriteProcessMemory_4db1 {
  strings:
    $key_4db1 = { 1a c3 [2] 28 e1 [2] 2e d4 [2] 00 d4 [2] 3f c8 }

  condition:
    any of them
}