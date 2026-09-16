rule TTP_XOR_WriteProcessMemory_15bb {
  strings:
    $key_15bb = { 42 c9 [2] 70 eb [2] 76 de [2] 58 de [2] 67 c2 }

  condition:
    any of them
}