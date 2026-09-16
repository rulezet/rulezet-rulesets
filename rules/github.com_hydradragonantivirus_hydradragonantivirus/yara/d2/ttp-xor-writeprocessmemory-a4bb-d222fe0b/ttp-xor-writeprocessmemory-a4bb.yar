rule TTP_XOR_WriteProcessMemory_a4bb {
  strings:
    $key_a4bb = { f3 c9 [2] c1 eb [2] c7 de [2] e9 de [2] d6 c2 }

  condition:
    any of them
}