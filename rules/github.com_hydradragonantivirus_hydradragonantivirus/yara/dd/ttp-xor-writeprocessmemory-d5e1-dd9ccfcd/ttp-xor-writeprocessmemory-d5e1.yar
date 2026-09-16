rule TTP_XOR_WriteProcessMemory_d5e1 {
  strings:
    $key_d5e1 = { 82 93 [2] b0 b1 [2] b6 84 [2] 98 84 [2] a7 98 }

  condition:
    any of them
}