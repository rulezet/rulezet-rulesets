rule TTP_XOR_WriteProcessMemory_8ab3 {
  strings:
    $key_8ab3 = { dd c1 [2] ef e3 [2] e9 d6 [2] c7 d6 [2] f8 ca }

  condition:
    any of them
}