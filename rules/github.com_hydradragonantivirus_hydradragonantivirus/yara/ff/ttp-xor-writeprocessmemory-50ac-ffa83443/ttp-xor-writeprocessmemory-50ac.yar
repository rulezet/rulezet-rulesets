rule TTP_XOR_WriteProcessMemory_50ac {
  strings:
    $key_50ac = { 07 de [2] 35 fc [2] 33 c9 [2] 1d c9 [2] 22 d5 }

  condition:
    any of them
}