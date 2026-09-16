rule TTP_XOR_WriteProcessMemory_8aee {
  strings:
    $key_8aee = { dd 9c [2] ef be [2] e9 8b [2] c7 8b [2] f8 97 }

  condition:
    any of them
}