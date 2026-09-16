rule TTP_XOR_WriteProcessMemory_c3d5 {
  strings:
    $key_c3d5 = { 94 a7 [2] a6 85 [2] a0 b0 [2] 8e b0 [2] b1 ac }

  condition:
    any of them
}