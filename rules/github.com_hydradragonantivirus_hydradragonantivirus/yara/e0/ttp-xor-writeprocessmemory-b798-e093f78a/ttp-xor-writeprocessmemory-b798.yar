rule TTP_XOR_WriteProcessMemory_b798 {
  strings:
    $key_b798 = { e0 ea [2] d2 c8 [2] d4 fd [2] fa fd [2] c5 e1 }

  condition:
    any of them
}