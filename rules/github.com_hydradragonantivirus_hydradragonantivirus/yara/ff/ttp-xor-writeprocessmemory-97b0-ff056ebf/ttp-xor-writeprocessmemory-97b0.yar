rule TTP_XOR_WriteProcessMemory_97b0 {
  strings:
    $key_97b0 = { c0 c2 [2] f2 e0 [2] f4 d5 [2] da d5 [2] e5 c9 }

  condition:
    any of them
}