rule TTP_XOR_WriteProcessMemory_9732 {
  strings:
    $key_9732 = { c0 40 [2] f2 62 [2] f4 57 [2] da 57 [2] e5 4b }

  condition:
    any of them
}