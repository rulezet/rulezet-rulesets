rule TTP_XOR_WriteProcessMemory_768e {
  strings:
    $key_768e = { 21 fc [2] 13 de [2] 15 eb [2] 3b eb [2] 04 f7 }

  condition:
    any of them
}