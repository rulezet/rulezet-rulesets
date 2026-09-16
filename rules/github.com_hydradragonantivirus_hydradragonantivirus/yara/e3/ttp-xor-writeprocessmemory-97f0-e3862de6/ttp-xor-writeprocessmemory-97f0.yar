rule TTP_XOR_WriteProcessMemory_97f0 {
  strings:
    $key_97f0 = { c0 82 [2] f2 a0 [2] f4 95 [2] da 95 [2] e5 89 }

  condition:
    any of them
}