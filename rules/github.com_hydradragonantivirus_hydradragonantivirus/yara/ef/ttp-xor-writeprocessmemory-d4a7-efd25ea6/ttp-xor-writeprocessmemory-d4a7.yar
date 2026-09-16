rule TTP_XOR_WriteProcessMemory_d4a7 {
  strings:
    $key_d4a7 = { 83 d5 [2] b1 f7 [2] b7 c2 [2] 99 c2 [2] a6 de }

  condition:
    any of them
}