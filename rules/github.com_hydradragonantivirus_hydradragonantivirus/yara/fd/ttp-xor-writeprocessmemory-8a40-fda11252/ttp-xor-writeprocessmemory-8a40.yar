rule TTP_XOR_WriteProcessMemory_8a40 {
  strings:
    $key_8a40 = { dd 32 [2] ef 10 [2] e9 25 [2] c7 25 [2] f8 39 }

  condition:
    any of them
}