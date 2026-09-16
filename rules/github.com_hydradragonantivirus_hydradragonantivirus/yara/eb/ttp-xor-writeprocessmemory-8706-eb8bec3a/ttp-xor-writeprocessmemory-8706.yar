rule TTP_XOR_WriteProcessMemory_8706 {
  strings:
    $key_8706 = { d0 74 [2] e2 56 [2] e4 63 [2] ca 63 [2] f5 7f }

  condition:
    any of them
}