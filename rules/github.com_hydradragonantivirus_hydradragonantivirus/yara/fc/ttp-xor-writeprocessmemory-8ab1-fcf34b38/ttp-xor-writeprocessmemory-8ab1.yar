rule TTP_XOR_WriteProcessMemory_8ab1 {
  strings:
    $key_8ab1 = { dd c3 [2] ef e1 [2] e9 d4 [2] c7 d4 [2] f8 c8 }

  condition:
    any of them
}