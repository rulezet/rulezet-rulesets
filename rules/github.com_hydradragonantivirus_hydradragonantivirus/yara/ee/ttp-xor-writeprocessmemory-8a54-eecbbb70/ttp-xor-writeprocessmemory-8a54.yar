rule TTP_XOR_WriteProcessMemory_8a54 {
  strings:
    $key_8a54 = { dd 26 [2] ef 04 [2] e9 31 [2] c7 31 [2] f8 2d }

  condition:
    any of them
}