rule TTP_XOR_WriteProcessMemory_c4e1 {
  strings:
    $key_c4e1 = { 93 93 [2] a1 b1 [2] a7 84 [2] 89 84 [2] b6 98 }

  condition:
    any of them
}