rule TTP_XOR_WriteProcessMemory_928e {
  strings:
    $key_928e = { c5 fc [2] f7 de [2] f1 eb [2] df eb [2] e0 f7 }

  condition:
    any of them
}