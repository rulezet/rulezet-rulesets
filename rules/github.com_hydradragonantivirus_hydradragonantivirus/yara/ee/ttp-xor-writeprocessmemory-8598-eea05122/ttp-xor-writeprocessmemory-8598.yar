rule TTP_XOR_WriteProcessMemory_8598 {
  strings:
    $key_8598 = { d2 ea [2] e0 c8 [2] e6 fd [2] c8 fd [2] f7 e1 }

  condition:
    any of them
}