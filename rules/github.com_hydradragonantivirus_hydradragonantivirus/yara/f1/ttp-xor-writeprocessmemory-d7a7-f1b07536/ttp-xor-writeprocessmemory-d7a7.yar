rule TTP_XOR_WriteProcessMemory_d7a7 {
  strings:
    $key_d7a7 = { 80 d5 [2] b2 f7 [2] b4 c2 [2] 9a c2 [2] a5 de }

  condition:
    any of them
}