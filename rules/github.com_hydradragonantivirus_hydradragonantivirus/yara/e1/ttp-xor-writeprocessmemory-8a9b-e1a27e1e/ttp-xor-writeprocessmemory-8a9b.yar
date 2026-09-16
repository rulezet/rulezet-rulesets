rule TTP_XOR_WriteProcessMemory_8a9b {
  strings:
    $key_8a9b = { dd e9 [2] ef cb [2] e9 fe [2] c7 fe [2] f8 e2 }

  condition:
    any of them
}