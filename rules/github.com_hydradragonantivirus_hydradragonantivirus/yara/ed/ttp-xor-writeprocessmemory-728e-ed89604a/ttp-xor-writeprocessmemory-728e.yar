rule TTP_XOR_WriteProcessMemory_728e {
  strings:
    $key_728e = { 25 fc [2] 17 de [2] 11 eb [2] 3f eb [2] 00 f7 }

  condition:
    any of them
}