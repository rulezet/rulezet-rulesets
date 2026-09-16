rule TTP_XOR_WriteProcessMemory_a5b1 {
  strings:
    $key_a5b1 = { f2 c3 [2] c0 e1 [2] c6 d4 [2] e8 d4 [2] d7 c8 }

  condition:
    any of them
}