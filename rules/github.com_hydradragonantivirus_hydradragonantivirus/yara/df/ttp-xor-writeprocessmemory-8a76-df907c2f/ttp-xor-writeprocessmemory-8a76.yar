rule TTP_XOR_WriteProcessMemory_8a76 {
  strings:
    $key_8a76 = { dd 04 [2] ef 26 [2] e9 13 [2] c7 13 [2] f8 0f }

  condition:
    any of them
}