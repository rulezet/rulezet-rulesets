rule TTP_XOR_WriteProcessMemory_97f7 {
  strings:
    $key_97f7 = { c0 85 [2] f2 a7 [2] f4 92 [2] da 92 [2] e5 8e }

  condition:
    any of them
}