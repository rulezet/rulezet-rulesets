rule TTP_XOR_WriteProcessMemory_a7b1 {
  strings:
    $key_a7b1 = { f0 c3 [2] c2 e1 [2] c4 d4 [2] ea d4 [2] d5 c8 }

  condition:
    any of them
}