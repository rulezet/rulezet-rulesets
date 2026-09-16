rule TTP_XOR_WriteProcessMemory_c0a7 {
  strings:
    $key_c0a7 = { 97 d5 [2] a5 f7 [2] a3 c2 [2] 8d c2 [2] b2 de }

  condition:
    any of them
}