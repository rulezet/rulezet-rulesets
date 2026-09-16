rule TTP_XOR_WriteProcessMemory_92ac {
  strings:
    $key_92ac = { c5 de [2] f7 fc [2] f1 c9 [2] df c9 [2] e0 d5 }

  condition:
    any of them
}