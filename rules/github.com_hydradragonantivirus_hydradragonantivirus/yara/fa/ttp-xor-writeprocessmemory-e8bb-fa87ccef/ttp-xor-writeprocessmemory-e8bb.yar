rule TTP_XOR_WriteProcessMemory_e8bb {
  strings:
    $key_e8bb = { bf c9 [2] 8d eb [2] 8b de [2] a5 de [2] 9a c2 }

  condition:
    any of them
}