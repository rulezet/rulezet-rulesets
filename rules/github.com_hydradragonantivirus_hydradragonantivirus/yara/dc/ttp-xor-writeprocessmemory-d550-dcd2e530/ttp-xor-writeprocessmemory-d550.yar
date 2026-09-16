rule TTP_XOR_WriteProcessMemory_d550 {
  strings:
    $key_d550 = { 82 22 [2] b0 00 [2] b6 35 [2] 98 35 [2] a7 29 }

  condition:
    any of them
}