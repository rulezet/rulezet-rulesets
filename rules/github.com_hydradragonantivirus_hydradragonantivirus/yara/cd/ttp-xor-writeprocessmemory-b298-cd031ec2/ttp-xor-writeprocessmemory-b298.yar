rule TTP_XOR_WriteProcessMemory_b298 {
  strings:
    $key_b298 = { e5 ea [2] d7 c8 [2] d1 fd [2] ff fd [2] c0 e1 }

  condition:
    any of them
}