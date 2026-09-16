rule TTP_XOR_WriteProcessMemory_1fbb {
  strings:
    $key_1fbb = { 48 c9 [2] 7a eb [2] 7c de [2] 52 de [2] 6d c2 }

  condition:
    any of them
}