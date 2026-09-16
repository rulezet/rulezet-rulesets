rule TTP_XOR_WriteProcessMemory_a7a0 {
  strings:
    $key_a7a0 = { f0 d2 [2] c2 f0 [2] c4 c5 [2] ea c5 [2] d5 d9 }

  condition:
    any of them
}