rule TTP_XOR_WriteProcessMemory_8ac1 {
  strings:
    $key_8ac1 = { dd b3 [2] ef 91 [2] e9 a4 [2] c7 a4 [2] f8 b8 }

  condition:
    any of them
}