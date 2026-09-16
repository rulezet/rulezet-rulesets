rule TTP_XOR_WriteProcessMemory_108e {
  strings:
    $key_108e = { 47 fc [2] 75 de [2] 73 eb [2] 5d eb [2] 62 f7 }

  condition:
    any of them
}