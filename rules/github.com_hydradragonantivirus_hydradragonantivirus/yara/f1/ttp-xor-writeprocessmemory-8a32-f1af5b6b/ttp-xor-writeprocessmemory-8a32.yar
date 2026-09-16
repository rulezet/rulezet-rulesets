rule TTP_XOR_WriteProcessMemory_8a32 {
  strings:
    $key_8a32 = { dd 40 [2] ef 62 [2] e9 57 [2] c7 57 [2] f8 4b }

  condition:
    any of them
}