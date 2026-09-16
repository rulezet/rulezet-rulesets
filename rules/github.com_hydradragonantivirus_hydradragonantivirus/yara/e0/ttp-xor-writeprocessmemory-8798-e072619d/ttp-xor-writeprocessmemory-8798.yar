rule TTP_XOR_WriteProcessMemory_8798 {
  strings:
    $key_8798 = { d0 ea [2] e2 c8 [2] e4 fd [2] ca fd [2] f5 e1 }

  condition:
    any of them
}