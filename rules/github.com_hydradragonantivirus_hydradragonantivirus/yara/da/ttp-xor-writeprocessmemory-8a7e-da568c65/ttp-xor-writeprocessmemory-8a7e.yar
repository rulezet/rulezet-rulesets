rule TTP_XOR_WriteProcessMemory_8a7e {
  strings:
    $key_8a7e = { dd 0c [2] ef 2e [2] e9 1b [2] c7 1b [2] f8 07 }

  condition:
    any of them
}