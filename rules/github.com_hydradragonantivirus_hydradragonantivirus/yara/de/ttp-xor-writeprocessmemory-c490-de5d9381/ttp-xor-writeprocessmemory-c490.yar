rule TTP_XOR_WriteProcessMemory_c490 {
  strings:
    $key_c490 = { 93 e2 [2] a1 c0 [2] a7 f5 [2] 89 f5 [2] b6 e9 }

  condition:
    any of them
}