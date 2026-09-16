rule TTP_XOR_WriteProcessMemory_8a45 {
  strings:
    $key_8a45 = { dd 37 [2] ef 15 [2] e9 20 [2] c7 20 [2] f8 3c }

  condition:
    any of them
}