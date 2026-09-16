rule TTP_XOR_WriteProcessMemory_c3a3 {
  strings:
    $key_c3a3 = { 94 d1 [2] a6 f3 [2] a0 c6 [2] 8e c6 [2] b1 da }

  condition:
    any of them
}