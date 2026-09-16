rule TTP_XOR_WriteProcessMemory_c491 {
  strings:
    $key_c491 = { 93 e3 [2] a1 c1 [2] a7 f4 [2] 89 f4 [2] b6 e8 }

  condition:
    any of them
}