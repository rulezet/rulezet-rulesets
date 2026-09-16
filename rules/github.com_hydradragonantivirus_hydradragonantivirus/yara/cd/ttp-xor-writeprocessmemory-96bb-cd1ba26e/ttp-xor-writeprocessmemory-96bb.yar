rule TTP_XOR_WriteProcessMemory_96bb {
  strings:
    $key_96bb = { c1 c9 [2] f3 eb [2] f5 de [2] db de [2] e4 c2 }

  condition:
    any of them
}