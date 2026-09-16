rule TTP_XOR_WriteProcessMemory_b398 {
  strings:
    $key_b398 = { e4 ea [2] d6 c8 [2] d0 fd [2] fe fd [2] c1 e1 }

  condition:
    any of them
}