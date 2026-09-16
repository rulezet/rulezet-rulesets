rule TTP_XOR_WriteProcessMemory_8121 {
  strings:
    $key_8121 = { d6 53 [2] e4 71 [2] e2 44 [2] cc 44 [2] f3 58 }

  condition:
    any of them
}