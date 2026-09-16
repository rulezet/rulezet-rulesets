rule TTP_XOR_WriteProcessMemory_87bb {
  strings:
    $key_87bb = { d0 c9 [2] e2 eb [2] e4 de [2] ca de [2] f5 c2 }

  condition:
    any of them
}