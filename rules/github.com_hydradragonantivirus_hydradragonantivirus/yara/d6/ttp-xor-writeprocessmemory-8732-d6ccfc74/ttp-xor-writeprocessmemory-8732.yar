rule TTP_XOR_WriteProcessMemory_8732 {
  strings:
    $key_8732 = { d0 40 [2] e2 62 [2] e4 57 [2] ca 57 [2] f5 4b }

  condition:
    any of them
}