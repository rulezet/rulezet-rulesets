rule TTP_XOR_WriteProcessMemory_c3c1 {
  strings:
    $key_c3c1 = { 94 b3 [2] a6 91 [2] a0 a4 [2] 8e a4 [2] b1 b8 }

  condition:
    any of them
}