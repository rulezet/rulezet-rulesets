rule TTP_XOR_WriteProcessMemory_1c8e {
  strings:
    $key_1c8e = { 4b fc [2] 79 de [2] 7f eb [2] 51 eb [2] 6e f7 }

  condition:
    any of them
}