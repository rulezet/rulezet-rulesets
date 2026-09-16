rule TTP_XOR_WriteProcessMemory_8167 {
  strings:
    $key_8167 = { d6 15 [2] e4 37 [2] e2 02 [2] cc 02 [2] f3 1e }

  condition:
    any of them
}