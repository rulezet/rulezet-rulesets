rule TTP_XOR_WriteProcessMemory_c581 {
  strings:
    $key_c581 = { 92 f3 [2] a0 d1 [2] a6 e4 [2] 88 e4 [2] b7 f8 }

  condition:
    any of them
}