rule TTP_XOR_WriteProcessMemory_5fbb {
  strings:
    $key_5fbb = { 08 c9 [2] 3a eb [2] 3c de [2] 12 de [2] 2d c2 }

  condition:
    any of them
}