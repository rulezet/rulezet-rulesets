rule TTP_XOR_WriteProcessMemory_98bb {
  strings:
    $key_98bb = { cf c9 [2] fd eb [2] fb de [2] d5 de [2] ea c2 }

  condition:
    any of them
}