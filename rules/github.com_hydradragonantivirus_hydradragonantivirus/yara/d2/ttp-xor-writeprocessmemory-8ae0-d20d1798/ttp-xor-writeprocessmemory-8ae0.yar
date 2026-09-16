rule TTP_XOR_WriteProcessMemory_8ae0 {
  strings:
    $key_8ae0 = { dd 92 [2] ef b0 [2] e9 85 [2] c7 85 [2] f8 99 }

  condition:
    any of them
}