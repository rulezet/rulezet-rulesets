rule TTP_XOR_WriteProcessMemory_8363 {
  strings:
    $key_8363 = { d4 11 [2] e6 33 [2] e0 06 [2] ce 06 [2] f1 1a }

  condition:
    any of them
}