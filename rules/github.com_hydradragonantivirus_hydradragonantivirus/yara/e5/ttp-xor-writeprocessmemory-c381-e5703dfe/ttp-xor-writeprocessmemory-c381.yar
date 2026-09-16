rule TTP_XOR_WriteProcessMemory_c381 {
  strings:
    $key_c381 = { 94 f3 [2] a6 d1 [2] a0 e4 [2] 8e e4 [2] b1 f8 }

  condition:
    any of them
}