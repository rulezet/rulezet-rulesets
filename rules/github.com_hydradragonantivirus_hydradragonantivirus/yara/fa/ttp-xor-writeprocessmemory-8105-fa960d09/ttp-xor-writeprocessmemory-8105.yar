rule TTP_XOR_WriteProcessMemory_8105 {
  strings:
    $key_8105 = { d6 77 [2] e4 55 [2] e2 60 [2] cc 60 [2] f3 7c }

  condition:
    any of them
}