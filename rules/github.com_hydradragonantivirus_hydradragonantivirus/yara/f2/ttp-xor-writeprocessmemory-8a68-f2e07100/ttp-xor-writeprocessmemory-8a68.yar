rule TTP_XOR_WriteProcessMemory_8a68 {
  strings:
    $key_8a68 = { dd 1a [2] ef 38 [2] e9 0d [2] c7 0d [2] f8 11 }

  condition:
    any of them
}