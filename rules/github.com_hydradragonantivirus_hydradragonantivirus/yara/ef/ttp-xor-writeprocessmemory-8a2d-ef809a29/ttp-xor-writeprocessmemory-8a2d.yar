rule TTP_XOR_WriteProcessMemory_8a2d {
  strings:
    $key_8a2d = { dd 5f [2] ef 7d [2] e9 48 [2] c7 48 [2] f8 54 }

  condition:
    any of them
}