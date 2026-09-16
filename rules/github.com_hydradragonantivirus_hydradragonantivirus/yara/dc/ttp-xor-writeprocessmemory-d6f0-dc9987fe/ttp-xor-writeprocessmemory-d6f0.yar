rule TTP_XOR_WriteProcessMemory_d6f0 {
  strings:
    $key_d6f0 = { 81 82 [2] b3 a0 [2] b5 95 [2] 9b 95 [2] a4 89 }

  condition:
    any of them
}