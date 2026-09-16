rule TTP_XOR_WriteProcessMemory_9743 {
  strings:
    $key_9743 = { c0 31 [2] f2 13 [2] f4 26 [2] da 26 [2] e5 3a }

  condition:
    any of them
}