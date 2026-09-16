rule TTP_XOR_WriteProcessMemory_8746 {
  strings:
    $key_8746 = { d0 34 [2] e2 16 [2] e4 23 [2] ca 23 [2] f5 3f }

  condition:
    any of them
}