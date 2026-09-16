rule TTP_XOR_WriteProcessMemory_8a10 {
  strings:
    $key_8a10 = { dd 62 [2] ef 40 [2] e9 75 [2] c7 75 [2] f8 69 }

  condition:
    any of them
}