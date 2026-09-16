rule TTP_XOR_WriteProcessMemory_c3d6 {
  strings:
    $key_c3d6 = { 94 a4 [2] a6 86 [2] a0 b3 [2] 8e b3 [2] b1 af }

  condition:
    any of them
}