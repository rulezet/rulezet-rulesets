rule TTP_XOR_WriteProcessMemory_c3a4 {
  strings:
    $key_c3a4 = { 94 d6 [2] a6 f4 [2] a0 c1 [2] 8e c1 [2] b1 dd }

  condition:
    any of them
}