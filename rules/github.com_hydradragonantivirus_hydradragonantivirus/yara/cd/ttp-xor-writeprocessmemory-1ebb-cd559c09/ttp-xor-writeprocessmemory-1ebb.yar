rule TTP_XOR_WriteProcessMemory_1ebb {
  strings:
    $key_1ebb = { 49 c9 [2] 7b eb [2] 7d de [2] 53 de [2] 6c c2 }

  condition:
    any of them
}