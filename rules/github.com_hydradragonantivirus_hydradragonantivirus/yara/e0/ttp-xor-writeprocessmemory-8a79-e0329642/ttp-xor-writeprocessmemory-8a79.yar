rule TTP_XOR_WriteProcessMemory_8a79 {
  strings:
    $key_8a79 = { dd 0b [2] ef 29 [2] e9 1c [2] c7 1c [2] f8 00 }

  condition:
    any of them
}