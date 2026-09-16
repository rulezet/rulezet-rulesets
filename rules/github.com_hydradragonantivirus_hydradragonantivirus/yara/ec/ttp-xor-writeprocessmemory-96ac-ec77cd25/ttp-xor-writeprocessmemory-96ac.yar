rule TTP_XOR_WriteProcessMemory_96ac {
  strings:
    $key_96ac = { c1 de [2] f3 fc [2] f5 c9 [2] db c9 [2] e4 d5 }

  condition:
    any of them
}