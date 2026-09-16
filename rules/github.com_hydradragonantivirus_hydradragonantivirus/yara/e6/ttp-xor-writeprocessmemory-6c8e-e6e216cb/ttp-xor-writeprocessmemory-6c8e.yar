rule TTP_XOR_WriteProcessMemory_6c8e {
  strings:
    $key_6c8e = { 3b fc [2] 09 de [2] 0f eb [2] 21 eb [2] 1e f7 }

  condition:
    any of them
}