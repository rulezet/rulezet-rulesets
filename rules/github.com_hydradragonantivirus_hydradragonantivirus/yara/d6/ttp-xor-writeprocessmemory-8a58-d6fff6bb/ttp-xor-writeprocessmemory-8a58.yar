rule TTP_XOR_WriteProcessMemory_8a58 {
  strings:
    $key_8a58 = { dd 2a [2] ef 08 [2] e9 3d [2] c7 3d [2] f8 21 }

  condition:
    any of them
}