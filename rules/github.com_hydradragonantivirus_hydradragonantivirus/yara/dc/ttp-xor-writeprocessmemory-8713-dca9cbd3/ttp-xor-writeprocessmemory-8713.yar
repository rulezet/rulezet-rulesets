rule TTP_XOR_WriteProcessMemory_8713 {
  strings:
    $key_8713 = { d0 61 [2] e2 43 [2] e4 76 [2] ca 76 [2] f5 6a }

  condition:
    any of them
}