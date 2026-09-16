rule TTP_XOR_WriteProcessMemory_8a46 {
  strings:
    $key_8a46 = { dd 34 [2] ef 16 [2] e9 23 [2] c7 23 [2] f8 3f }

  condition:
    any of them
}