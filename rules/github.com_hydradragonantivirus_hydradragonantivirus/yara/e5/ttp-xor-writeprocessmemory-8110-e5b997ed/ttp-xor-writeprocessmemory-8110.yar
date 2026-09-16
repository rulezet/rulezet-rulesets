rule TTP_XOR_WriteProcessMemory_8110 {
  strings:
    $key_8110 = { d6 62 [2] e4 40 [2] e2 75 [2] cc 75 [2] f3 69 }

  condition:
    any of them
}