rule TTP_XOR_WriteProcessMemory_278e {
  strings:
    $key_278e = { 70 fc [2] 42 de [2] 44 eb [2] 6a eb [2] 55 f7 }

  condition:
    any of them
}