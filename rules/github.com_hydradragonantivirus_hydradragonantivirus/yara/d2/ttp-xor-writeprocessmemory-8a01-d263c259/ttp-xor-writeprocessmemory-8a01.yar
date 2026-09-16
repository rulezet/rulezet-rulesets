rule TTP_XOR_WriteProcessMemory_8a01 {
  strings:
    $key_8a01 = { dd 73 [2] ef 51 [2] e9 64 [2] c7 64 [2] f8 78 }

  condition:
    any of them
}