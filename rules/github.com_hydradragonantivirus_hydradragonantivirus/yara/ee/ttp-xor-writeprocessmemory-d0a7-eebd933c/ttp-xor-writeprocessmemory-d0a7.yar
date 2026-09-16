rule TTP_XOR_WriteProcessMemory_d0a7 {
  strings:
    $key_d0a7 = { 87 d5 [2] b5 f7 [2] b3 c2 [2] 9d c2 [2] a2 de }

  condition:
    any of them
}