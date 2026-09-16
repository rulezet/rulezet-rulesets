rule TTP_XOR_WriteProcessMemory_c390 {
  strings:
    $key_c390 = { 94 e2 [2] a6 c0 [2] a0 f5 [2] 8e f5 [2] b1 e9 }

  condition:
    any of them
}