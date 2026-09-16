rule TTP_XOR_WriteProcessMemory_c3e1 {
  strings:
    $key_c3e1 = { 94 93 [2] a6 b1 [2] a0 84 [2] 8e 84 [2] b1 98 }

  condition:
    any of them
}