rule TTP_XOR_WriteProcessMemory_8a24 {
  strings:
    $key_8a24 = { dd 56 [2] ef 74 [2] e9 41 [2] c7 41 [2] f8 5d }

  condition:
    any of them
}