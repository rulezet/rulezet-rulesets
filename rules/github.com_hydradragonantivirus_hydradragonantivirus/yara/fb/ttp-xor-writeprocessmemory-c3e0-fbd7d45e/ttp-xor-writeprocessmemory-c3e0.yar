rule TTP_XOR_WriteProcessMemory_c3e0 {
  strings:
    $key_c3e0 = { 94 92 [2] a6 b0 [2] a0 85 [2] 8e 85 [2] b1 99 }

  condition:
    any of them
}