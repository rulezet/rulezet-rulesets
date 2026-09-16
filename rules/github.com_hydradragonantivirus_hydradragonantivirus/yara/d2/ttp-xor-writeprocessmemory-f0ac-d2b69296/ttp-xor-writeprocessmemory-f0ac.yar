rule TTP_XOR_WriteProcessMemory_f0ac {
  strings:
    $key_f0ac = { a7 de [2] 95 fc [2] 93 c9 [2] bd c9 [2] 82 d5 }

  condition:
    any of them
}