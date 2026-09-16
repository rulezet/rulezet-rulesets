rule TTP_XOR_WriteProcessMemory_8129 {
  strings:
    $key_8129 = { d6 5b [2] e4 79 [2] e2 4c [2] cc 4c [2] f3 50 }

  condition:
    any of them
}