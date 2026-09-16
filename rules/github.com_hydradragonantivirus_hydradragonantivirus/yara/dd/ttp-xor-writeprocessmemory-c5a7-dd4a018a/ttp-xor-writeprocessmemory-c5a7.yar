rule TTP_XOR_WriteProcessMemory_c5a7 {
  strings:
    $key_c5a7 = { 92 d5 [2] a0 f7 [2] a6 c2 [2] 88 c2 [2] b7 de }

  condition:
    any of them
}