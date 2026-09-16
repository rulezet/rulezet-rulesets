rule TTP_XOR_WriteProcessMemory_128e {
  strings:
    $key_128e = { 45 fc [2] 77 de [2] 71 eb [2] 5f eb [2] 60 f7 }

  condition:
    any of them
}