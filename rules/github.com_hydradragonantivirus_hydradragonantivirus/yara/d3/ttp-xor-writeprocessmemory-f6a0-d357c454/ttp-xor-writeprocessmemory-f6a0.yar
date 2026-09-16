rule TTP_XOR_WriteProcessMemory_f6a0 {
  strings:
    $key_f6a0 = { a1 d2 [2] 93 f0 [2] 95 c5 [2] bb c5 [2] 84 d9 }

  condition:
    any of them
}