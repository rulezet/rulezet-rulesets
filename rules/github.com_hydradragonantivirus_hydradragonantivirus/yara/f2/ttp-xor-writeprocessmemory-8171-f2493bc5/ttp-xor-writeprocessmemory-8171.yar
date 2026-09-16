rule TTP_XOR_WriteProcessMemory_8171 {
  strings:
    $key_8171 = { d6 03 [2] e4 21 [2] e2 14 [2] cc 14 [2] f3 08 }

  condition:
    any of them
}