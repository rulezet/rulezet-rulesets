rule TTP_XOR_WriteProcessMemory_8a50 {
  strings:
    $key_8a50 = { dd 22 [2] ef 00 [2] e9 35 [2] c7 35 [2] f8 29 }

  condition:
    any of them
}