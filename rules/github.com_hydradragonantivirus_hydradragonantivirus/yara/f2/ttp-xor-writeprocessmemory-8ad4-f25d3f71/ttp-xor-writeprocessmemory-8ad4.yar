rule TTP_XOR_WriteProcessMemory_8ad4 {
  strings:
    $key_8ad4 = { dd a6 [2] ef 84 [2] e9 b1 [2] c7 b1 [2] f8 ad }

  condition:
    any of them
}