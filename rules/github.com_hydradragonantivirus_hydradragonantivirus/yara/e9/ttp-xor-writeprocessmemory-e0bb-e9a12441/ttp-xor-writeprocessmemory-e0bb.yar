rule TTP_XOR_WriteProcessMemory_e0bb {
  strings:
    $key_e0bb = { b7 c9 [2] 85 eb [2] 83 de [2] ad de [2] 92 c2 }

  condition:
    any of them
}