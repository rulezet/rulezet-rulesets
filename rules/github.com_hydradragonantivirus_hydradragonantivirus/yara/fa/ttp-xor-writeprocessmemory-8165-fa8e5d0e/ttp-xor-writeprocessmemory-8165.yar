rule TTP_XOR_WriteProcessMemory_8165 {
  strings:
    $key_8165 = { d6 17 [2] e4 35 [2] e2 00 [2] cc 00 [2] f3 1c }

  condition:
    any of them
}