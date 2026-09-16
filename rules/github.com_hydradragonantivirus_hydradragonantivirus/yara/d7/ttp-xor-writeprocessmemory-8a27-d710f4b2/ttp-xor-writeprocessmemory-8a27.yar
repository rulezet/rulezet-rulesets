rule TTP_XOR_WriteProcessMemory_8a27 {
  strings:
    $key_8a27 = { dd 55 [2] ef 77 [2] e9 42 [2] c7 42 [2] f8 5e }

  condition:
    any of them
}