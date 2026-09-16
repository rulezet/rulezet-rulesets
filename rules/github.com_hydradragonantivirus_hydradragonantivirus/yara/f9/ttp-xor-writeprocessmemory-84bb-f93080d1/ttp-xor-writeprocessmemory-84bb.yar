rule TTP_XOR_WriteProcessMemory_84bb {
  strings:
    $key_84bb = { d3 c9 [2] e1 eb [2] e7 de [2] c9 de [2] f6 c2 }

  condition:
    any of them
}