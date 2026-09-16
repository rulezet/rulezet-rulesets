rule TTP_XOR_WriteProcessMemory_8178 {
  strings:
    $key_8178 = { d6 0a [2] e4 28 [2] e2 1d [2] cc 1d [2] f3 01 }

  condition:
    any of them
}