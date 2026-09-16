rule TTP_XOR_WriteProcessMemory_08bb {
  strings:
    $key_08bb = { 5f c9 [2] 6d eb [2] 6b de [2] 45 de [2] 7a c2 }

  condition:
    any of them
}