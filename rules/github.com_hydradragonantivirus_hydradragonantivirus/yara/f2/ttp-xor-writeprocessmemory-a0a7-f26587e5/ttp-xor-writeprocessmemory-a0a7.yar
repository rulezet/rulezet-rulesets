rule TTP_XOR_WriteProcessMemory_a0a7 {
  strings:
    $key_a0a7 = { f7 d5 [2] c5 f7 [2] c3 c2 [2] ed c2 [2] d2 de }

  condition:
    any of them
}