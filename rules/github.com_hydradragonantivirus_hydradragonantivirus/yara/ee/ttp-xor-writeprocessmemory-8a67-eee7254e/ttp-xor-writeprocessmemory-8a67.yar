rule TTP_XOR_WriteProcessMemory_8a67 {
  strings:
    $key_8a67 = { dd 15 [2] ef 37 [2] e9 02 [2] c7 02 [2] f8 1e }

  condition:
    any of them
}