rule TTP_XOR_WriteProcessMemory_78bb {
  strings:
    $key_78bb = { 2f c9 [2] 1d eb [2] 1b de [2] 35 de [2] 0a c2 }

  condition:
    any of them
}