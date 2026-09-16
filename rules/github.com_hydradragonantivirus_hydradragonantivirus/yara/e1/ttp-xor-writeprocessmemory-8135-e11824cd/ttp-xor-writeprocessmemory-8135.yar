rule TTP_XOR_WriteProcessMemory_8135 {
  strings:
    $key_8135 = { d6 47 [2] e4 65 [2] e2 50 [2] cc 50 [2] f3 4c }

  condition:
    any of them
}