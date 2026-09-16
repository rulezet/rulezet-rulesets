rule TTP_XOR_WriteProcessMemory_8ab4 {
  strings:
    $key_8ab4 = { dd c6 [2] ef e4 [2] e9 d1 [2] c7 d1 [2] f8 cd }

  condition:
    any of them
}