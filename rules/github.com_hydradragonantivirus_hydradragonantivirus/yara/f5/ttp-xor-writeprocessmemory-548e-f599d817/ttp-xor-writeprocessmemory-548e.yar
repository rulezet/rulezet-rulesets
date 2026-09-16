rule TTP_XOR_WriteProcessMemory_548e {
  strings:
    $key_548e = { 03 fc [2] 31 de [2] 37 eb [2] 19 eb [2] 26 f7 }

  condition:
    any of them
}