rule TTP_XOR_WriteProcessMemory_0e8e {
  strings:
    $key_0e8e = { 59 fc [2] 6b de [2] 6d eb [2] 43 eb [2] 7c f7 }

  condition:
    any of them
}