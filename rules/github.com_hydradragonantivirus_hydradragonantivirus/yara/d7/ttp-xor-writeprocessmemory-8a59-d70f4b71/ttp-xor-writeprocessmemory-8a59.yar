rule TTP_XOR_WriteProcessMemory_8a59 {
  strings:
    $key_8a59 = { dd 2b [2] ef 09 [2] e9 3c [2] c7 3c [2] f8 20 }

  condition:
    any of them
}