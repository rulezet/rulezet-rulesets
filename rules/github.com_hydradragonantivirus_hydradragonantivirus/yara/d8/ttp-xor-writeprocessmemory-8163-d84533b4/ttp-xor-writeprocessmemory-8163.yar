rule TTP_XOR_WriteProcessMemory_8163 {
  strings:
    $key_8163 = { d6 11 [2] e4 33 [2] e2 06 [2] cc 06 [2] f3 1a }

  condition:
    any of them
}