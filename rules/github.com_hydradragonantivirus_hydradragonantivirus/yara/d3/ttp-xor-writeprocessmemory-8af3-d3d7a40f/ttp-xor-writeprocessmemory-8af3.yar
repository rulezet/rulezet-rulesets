rule TTP_XOR_WriteProcessMemory_8af3 {
  strings:
    $key_8af3 = { dd 81 [2] ef a3 [2] e9 96 [2] c7 96 [2] f8 8a }

  condition:
    any of them
}