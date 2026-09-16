rule TTP_XOR_WriteProcessMemory_55bb {
  strings:
    $key_55bb = { 02 c9 [2] 30 eb [2] 36 de [2] 18 de [2] 27 c2 }

  condition:
    any of them
}