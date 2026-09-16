rule TTP_XOR_WriteProcessMemory_91e1 {
  strings:
    $key_91e1 = { c6 93 [2] f4 b1 [2] f2 84 [2] dc 84 [2] e3 98 }

  condition:
    any of them
}