rule TTP_XOR_WriteProcessMemory_c4a7 {
  strings:
    $key_c4a7 = { 93 d5 [2] a1 f7 [2] a7 c2 [2] 89 c2 [2] b6 de }

  condition:
    any of them
}