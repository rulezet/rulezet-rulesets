rule TTP_XOR_WriteProcessMemory_7ebb {
  strings:
    $key_7ebb = { 29 c9 [2] 1b eb [2] 1d de [2] 33 de [2] 0c c2 }

  condition:
    any of them
}