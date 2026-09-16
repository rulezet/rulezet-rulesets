rule TTP_XOR_WriteProcessMemory_adbb {
  strings:
    $key_adbb = { fa c9 [2] c8 eb [2] ce de [2] e0 de [2] df c2 }

  condition:
    any of them
}