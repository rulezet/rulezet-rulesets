rule TTP_XOR_WriteProcessMemory_8155 {
  strings:
    $key_8155 = { d6 27 [2] e4 05 [2] e2 30 [2] cc 30 [2] f3 2c }

  condition:
    any of them
}