rule TTP_XOR_WriteProcessMemory_8ae9 {
  strings:
    $key_8ae9 = { dd 9b [2] ef b9 [2] e9 8c [2] c7 8c [2] f8 90 }

  condition:
    any of them
}