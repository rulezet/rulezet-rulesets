rule TTP_XOR_WriteProcessMemory_c591 {
  strings:
    $key_c591 = { 92 e3 [2] a0 c1 [2] a6 f4 [2] 88 f4 [2] b7 e8 }

  condition:
    any of them
}