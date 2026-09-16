rule TTP_XOR_WriteProcessMemory_c3b1 {
  strings:
    $key_c3b1 = { 94 c3 [2] a6 e1 [2] a0 d4 [2] 8e d4 [2] b1 c8 }

  condition:
    any of them
}