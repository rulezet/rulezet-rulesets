rule TTP_XOR_WriteProcessMemory_c1f0 {
  strings:
    $key_c1f0 = { 96 82 [2] a4 a0 [2] a2 95 [2] 8c 95 [2] b3 89 }

  condition:
    any of them
}