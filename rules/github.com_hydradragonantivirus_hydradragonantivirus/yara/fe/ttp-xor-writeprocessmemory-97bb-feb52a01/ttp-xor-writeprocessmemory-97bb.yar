rule TTP_XOR_WriteProcessMemory_97bb {
  strings:
    $key_97bb = { c0 c9 [2] f2 eb [2] f4 de [2] da de [2] e5 c2 }

  condition:
    any of them
}