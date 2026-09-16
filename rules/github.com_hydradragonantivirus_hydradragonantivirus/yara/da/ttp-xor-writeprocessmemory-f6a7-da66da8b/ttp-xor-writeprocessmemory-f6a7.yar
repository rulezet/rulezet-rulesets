rule TTP_XOR_WriteProcessMemory_f6a7 {
  strings:
    $key_f6a7 = { a1 d5 [2] 93 f7 [2] 95 c2 [2] bb c2 [2] 84 de }

  condition:
    any of them
}