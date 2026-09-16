rule TTP_XOR_WriteProcessMemory_a7ac {
  strings:
    $key_a7ac = { f0 de [2] c2 fc [2] c4 c9 [2] ea c9 [2] d5 d5 }

  condition:
    any of them
}