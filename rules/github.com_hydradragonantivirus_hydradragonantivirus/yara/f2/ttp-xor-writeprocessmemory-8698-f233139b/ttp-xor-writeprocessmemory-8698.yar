rule TTP_XOR_WriteProcessMemory_8698 {
  strings:
    $key_8698 = { d1 ea [2] e3 c8 [2] e5 fd [2] cb fd [2] f4 e1 }

  condition:
    any of them
}