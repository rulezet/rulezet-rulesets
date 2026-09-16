rule TTP_XOR_WriteProcessMemory_048e {
  strings:
    $key_048e = { 53 fc [2] 61 de [2] 67 eb [2] 49 eb [2] 76 f7 }

  condition:
    any of them
}