rule TTP_XOR_WriteProcessMemory_92bb {
  strings:
    $key_92bb = { c5 c9 [2] f7 eb [2] f1 de [2] df de [2] e0 c2 }

  condition:
    any of them
}