rule TTP_XOR_WriteProcessMemory_468e {
  strings:
    $key_468e = { 11 fc [2] 23 de [2] 25 eb [2] 0b eb [2] 34 f7 }

  condition:
    any of them
}