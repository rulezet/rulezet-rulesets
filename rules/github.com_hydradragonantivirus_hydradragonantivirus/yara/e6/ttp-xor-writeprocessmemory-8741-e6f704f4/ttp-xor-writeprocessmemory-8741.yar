rule TTP_XOR_WriteProcessMemory_8741 {
  strings:
    $key_8741 = { d0 33 [2] e2 11 [2] e4 24 [2] ca 24 [2] f5 38 }

  condition:
    any of them
}