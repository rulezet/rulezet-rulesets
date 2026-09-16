rule TTP_XOR_WriteProcessMemory_8131 {
  strings:
    $key_8131 = { d6 43 [2] e4 61 [2] e2 54 [2] cc 54 [2] f3 48 }

  condition:
    any of them
}