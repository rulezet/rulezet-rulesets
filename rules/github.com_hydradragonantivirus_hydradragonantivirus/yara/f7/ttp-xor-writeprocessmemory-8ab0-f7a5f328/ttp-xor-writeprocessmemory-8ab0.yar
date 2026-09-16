rule TTP_XOR_WriteProcessMemory_8ab0 {
  strings:
    $key_8ab0 = { dd c2 [2] ef e0 [2] e9 d5 [2] c7 d5 [2] f8 c9 }

  condition:
    any of them
}