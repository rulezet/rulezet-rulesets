rule TTP_XOR_WriteProcessMemory_93bb {
  strings:
    $key_93bb = { c4 c9 [2] f6 eb [2] f0 de [2] de de [2] e1 c2 }

  condition:
    any of them
}