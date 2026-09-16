rule TTP_XOR_WriteProcessMemory_8dbb {
  strings:
    $key_8dbb = { da c9 [2] e8 eb [2] ee de [2] c0 de [2] ff c2 }

  condition:
    any of them
}