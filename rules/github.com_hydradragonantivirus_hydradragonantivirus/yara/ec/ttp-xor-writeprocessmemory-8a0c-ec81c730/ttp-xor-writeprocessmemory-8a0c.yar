rule TTP_XOR_WriteProcessMemory_8a0c {
  strings:
    $key_8a0c = { dd 7e [2] ef 5c [2] e9 69 [2] c7 69 [2] f8 75 }

  condition:
    any of them
}