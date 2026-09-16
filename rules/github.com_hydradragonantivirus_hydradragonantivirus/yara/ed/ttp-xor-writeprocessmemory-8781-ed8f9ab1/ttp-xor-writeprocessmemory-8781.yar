rule TTP_XOR_WriteProcessMemory_8781 {
  strings:
    $key_8781 = { d0 f3 [2] e2 d1 [2] e4 e4 [2] ca e4 [2] f5 f8 }

  condition:
    any of them
}