rule TTP_XOR_WriteProcessMemory_97e4 {
  strings:
    $key_97e4 = { c0 96 [2] f2 b4 [2] f4 81 [2] da 81 [2] e5 9d }

  condition:
    any of them
}