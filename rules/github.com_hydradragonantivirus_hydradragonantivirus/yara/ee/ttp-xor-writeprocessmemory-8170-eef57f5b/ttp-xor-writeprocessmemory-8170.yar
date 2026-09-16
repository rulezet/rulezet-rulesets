rule TTP_XOR_WriteProcessMemory_8170 {
  strings:
    $key_8170 = { d6 02 [2] e4 20 [2] e2 15 [2] cc 15 [2] f3 09 }

  condition:
    any of them
}