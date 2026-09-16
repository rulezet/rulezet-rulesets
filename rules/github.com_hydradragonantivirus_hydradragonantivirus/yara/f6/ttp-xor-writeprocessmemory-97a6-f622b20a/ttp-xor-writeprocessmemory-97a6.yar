rule TTP_XOR_WriteProcessMemory_97a6 {
  strings:
    $key_97a6 = { c0 d4 [2] f2 f6 [2] f4 c3 [2] da c3 [2] e5 df }

  condition:
    any of them
}