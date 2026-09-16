rule TTP_XOR_WriteProcessMemory_c3f0 {
  strings:
    $key_c3f0 = { 94 82 [2] a6 a0 [2] a0 95 [2] 8e 95 [2] b1 89 }

  condition:
    any of them
}