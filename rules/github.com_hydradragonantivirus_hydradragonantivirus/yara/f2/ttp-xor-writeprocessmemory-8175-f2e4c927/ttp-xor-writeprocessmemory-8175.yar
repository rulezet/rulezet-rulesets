rule TTP_XOR_WriteProcessMemory_8175 {
  strings:
    $key_8175 = { d6 07 [2] e4 25 [2] e2 10 [2] cc 10 [2] f3 0c }

  condition:
    any of them
}