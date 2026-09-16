rule TTP_XOR_WriteProcessMemory_428e {
  strings:
    $key_428e = { 15 fc [2] 27 de [2] 21 eb [2] 0f eb [2] 30 f7 }

  condition:
    any of them
}