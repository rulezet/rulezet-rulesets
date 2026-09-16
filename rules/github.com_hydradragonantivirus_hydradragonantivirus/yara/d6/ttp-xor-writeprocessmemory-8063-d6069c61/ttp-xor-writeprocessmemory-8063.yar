rule TTP_XOR_WriteProcessMemory_8063 {
  strings:
    $key_8063 = { d7 11 [2] e5 33 [2] e3 06 [2] cd 06 [2] f2 1a }

  condition:
    any of them
}