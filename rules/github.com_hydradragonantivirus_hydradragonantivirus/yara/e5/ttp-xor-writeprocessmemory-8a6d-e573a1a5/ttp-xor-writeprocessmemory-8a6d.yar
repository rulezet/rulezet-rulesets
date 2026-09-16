rule TTP_XOR_WriteProcessMemory_8a6d {
  strings:
    $key_8a6d = { dd 1f [2] ef 3d [2] e9 08 [2] c7 08 [2] f8 14 }

  condition:
    any of them
}