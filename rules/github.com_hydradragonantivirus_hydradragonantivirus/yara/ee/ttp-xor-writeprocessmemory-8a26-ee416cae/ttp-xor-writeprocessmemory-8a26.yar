rule TTP_XOR_WriteProcessMemory_8a26 {
  strings:
    $key_8a26 = { dd 54 [2] ef 76 [2] e9 43 [2] c7 43 [2] f8 5f }

  condition:
    any of them
}