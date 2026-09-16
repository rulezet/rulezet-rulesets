rule TTP_XOR_WriteProcessMemory_8398 {
  strings:
    $key_8398 = { d4 ea [2] e6 c8 [2] e0 fd [2] ce fd [2] f1 e1 }

  condition:
    any of them
}