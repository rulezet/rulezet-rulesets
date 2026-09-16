rule TTP_XOR_WriteProcessMemory_c3b0 {
  strings:
    $key_c3b0 = { 94 c2 [2] a6 e0 [2] a0 d5 [2] 8e d5 [2] b1 c9 }

  condition:
    any of them
}