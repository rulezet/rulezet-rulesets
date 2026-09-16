rule TTP_XOR_WriteProcessMemory_41bb {
  strings:
    $key_41bb = { 16 c9 [2] 24 eb [2] 22 de [2] 0c de [2] 33 c2 }

  condition:
    any of them
}