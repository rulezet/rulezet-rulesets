rule TTP_XOR_WriteProcessMemory_8a2a {
  strings:
    $key_8a2a = { dd 58 [2] ef 7a [2] e9 4f [2] c7 4f [2] f8 53 }

  condition:
    any of them
}