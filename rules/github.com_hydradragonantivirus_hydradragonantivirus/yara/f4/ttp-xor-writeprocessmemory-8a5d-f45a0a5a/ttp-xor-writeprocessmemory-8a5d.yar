rule TTP_XOR_WriteProcessMemory_8a5d {
  strings:
    $key_8a5d = { dd 2f [2] ef 0d [2] e9 38 [2] c7 38 [2] f8 24 }

  condition:
    any of them
}