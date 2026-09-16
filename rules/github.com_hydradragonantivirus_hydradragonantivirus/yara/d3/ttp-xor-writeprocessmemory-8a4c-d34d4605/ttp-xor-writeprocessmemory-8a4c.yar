rule TTP_XOR_WriteProcessMemory_8a4c {
  strings:
    $key_8a4c = { dd 3e [2] ef 1c [2] e9 29 [2] c7 29 [2] f8 35 }

  condition:
    any of them
}