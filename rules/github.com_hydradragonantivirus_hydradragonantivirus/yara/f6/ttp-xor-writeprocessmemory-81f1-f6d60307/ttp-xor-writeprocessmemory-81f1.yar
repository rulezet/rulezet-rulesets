rule TTP_XOR_WriteProcessMemory_81f1 {
  strings:
    $key_81f1 = { d6 83 [2] e4 a1 [2] e2 94 [2] cc 94 [2] f3 88 }

  condition:
    any of them
}