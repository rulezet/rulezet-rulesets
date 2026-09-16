rule TTP_XOR_WriteProcessMemory_20ac {
  strings:
    $key_20ac = { 77 de [2] 45 fc [2] 43 c9 [2] 6d c9 [2] 52 d5 }

  condition:
    any of them
}