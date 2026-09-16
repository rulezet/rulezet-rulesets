rule TTP_XOR_WriteProcessMemory_8a4a {
  strings:
    $key_8a4a = { dd 38 [2] ef 1a [2] e9 2f [2] c7 2f [2] f8 33 }

  condition:
    any of them
}