rule TTP_XOR_WriteProcessMemory_8743 {
  strings:
    $key_8743 = { d0 31 [2] e2 13 [2] e4 26 [2] ca 26 [2] f5 3a }

  condition:
    any of them
}