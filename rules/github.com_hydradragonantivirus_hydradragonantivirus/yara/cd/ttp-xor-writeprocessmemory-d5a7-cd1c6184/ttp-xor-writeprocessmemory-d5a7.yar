rule TTP_XOR_WriteProcessMemory_d5a7 {
  strings:
    $key_d5a7 = { 82 d5 [2] b0 f7 [2] b6 c2 [2] 98 c2 [2] a7 de }

  condition:
    any of them
}