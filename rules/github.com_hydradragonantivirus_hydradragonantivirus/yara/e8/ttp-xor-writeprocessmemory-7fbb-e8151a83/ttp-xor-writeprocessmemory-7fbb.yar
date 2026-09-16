rule TTP_XOR_WriteProcessMemory_7fbb {
  strings:
    $key_7fbb = { 28 c9 [2] 1a eb [2] 1c de [2] 32 de [2] 0d c2 }

  condition:
    any of them
}