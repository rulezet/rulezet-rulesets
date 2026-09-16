rule TTP_XOR_WriteProcessMemory_718e {
  strings:
    $key_718e = { 26 fc [2] 14 de [2] 12 eb [2] 3c eb [2] 03 f7 }

  condition:
    any of them
}