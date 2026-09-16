rule TTP_XOR_WriteProcessMemory_8a3b {
  strings:
    $key_8a3b = { dd 49 [2] ef 6b [2] e9 5e [2] c7 5e [2] f8 42 }

  condition:
    any of them
}