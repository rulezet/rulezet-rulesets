rule TTP_XOR_WriteProcessMemory_85ac {
  strings:
    $key_85ac = { d2 de [2] e0 fc [2] e6 c9 [2] c8 c9 [2] f7 d5 }

  condition:
    any of them
}