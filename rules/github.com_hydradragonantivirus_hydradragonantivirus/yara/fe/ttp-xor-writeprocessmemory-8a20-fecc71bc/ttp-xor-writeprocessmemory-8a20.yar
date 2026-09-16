rule TTP_XOR_WriteProcessMemory_8a20 {
  strings:
    $key_8a20 = { dd 52 [2] ef 70 [2] e9 45 [2] c7 45 [2] f8 59 }

  condition:
    any of them
}