rule TTP_XOR_WriteProcessMemory_c380 {
  strings:
    $key_c380 = { 94 f2 [2] a6 d0 [2] a0 e5 [2] 8e e5 [2] b1 f9 }

  condition:
    any of them
}