rule TTP_XOR_WriteProcessMemory_8ad3 {
  strings:
    $key_8ad3 = { dd a1 [2] ef 83 [2] e9 b6 [2] c7 b6 [2] f8 aa }

  condition:
    any of them
}