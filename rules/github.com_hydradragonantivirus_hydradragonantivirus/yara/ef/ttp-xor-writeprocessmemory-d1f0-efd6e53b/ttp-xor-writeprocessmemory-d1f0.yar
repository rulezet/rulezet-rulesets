rule TTP_XOR_WriteProcessMemory_d1f0 {
  strings:
    $key_d1f0 = { 86 82 [2] b4 a0 [2] b2 95 [2] 9c 95 [2] a3 89 }

  condition:
    any of them
}