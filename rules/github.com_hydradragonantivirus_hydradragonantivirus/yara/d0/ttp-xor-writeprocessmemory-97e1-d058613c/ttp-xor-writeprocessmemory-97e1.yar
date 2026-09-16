rule TTP_XOR_WriteProcessMemory_97e1 {
  strings:
    $key_97e1 = { c0 93 [2] f2 b1 [2] f4 84 [2] da 84 [2] e5 98 }

  condition:
    any of them
}