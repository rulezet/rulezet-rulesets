rule TTP_XOR_WriteProcessMemory_8a42 {
  strings:
    $key_8a42 = { dd 30 [2] ef 12 [2] e9 27 [2] c7 27 [2] f8 3b }

  condition:
    any of them
}