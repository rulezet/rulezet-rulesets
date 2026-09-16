rule TTP_XOR_WriteProcessMemory_8772 {
  strings:
    $key_8772 = { d0 00 [2] e2 22 [2] e4 17 [2] ca 17 [2] f5 0b }

  condition:
    any of them
}