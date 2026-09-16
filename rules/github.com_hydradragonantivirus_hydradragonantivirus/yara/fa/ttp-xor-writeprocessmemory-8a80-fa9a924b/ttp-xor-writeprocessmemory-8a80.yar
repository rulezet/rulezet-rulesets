rule TTP_XOR_WriteProcessMemory_8a80 {
  strings:
    $key_8a80 = { dd f2 [2] ef d0 [2] e9 e5 [2] c7 e5 [2] f8 f9 }

  condition:
    any of them
}