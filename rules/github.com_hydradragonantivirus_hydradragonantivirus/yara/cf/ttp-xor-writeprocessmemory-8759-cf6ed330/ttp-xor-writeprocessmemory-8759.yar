rule TTP_XOR_WriteProcessMemory_8759 {
  strings:
    $key_8759 = { d0 2b [2] e2 09 [2] e4 3c [2] ca 3c [2] f5 20 }

  condition:
    any of them
}