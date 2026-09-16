rule TTP_XOR_WriteProcessMemory_788e {
  strings:
    $key_788e = { 2f fc [2] 1d de [2] 1b eb [2] 35 eb [2] 0a f7 }

  condition:
    any of them
}