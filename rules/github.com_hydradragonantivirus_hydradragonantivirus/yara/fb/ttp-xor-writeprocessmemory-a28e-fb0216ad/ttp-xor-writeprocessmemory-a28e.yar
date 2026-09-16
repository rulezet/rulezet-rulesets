rule TTP_XOR_WriteProcessMemory_a28e {
  strings:
    $key_a28e = { f5 fc [2] c7 de [2] c1 eb [2] ef eb [2] d0 f7 }

  condition:
    any of them
}