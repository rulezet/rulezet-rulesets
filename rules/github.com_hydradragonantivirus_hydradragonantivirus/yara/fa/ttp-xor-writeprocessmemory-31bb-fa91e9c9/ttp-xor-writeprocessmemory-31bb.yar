rule TTP_XOR_WriteProcessMemory_31bb {
  strings:
    $key_31bb = { 66 c9 [2] 54 eb [2] 52 de [2] 7c de [2] 43 c2 }

  condition:
    any of them
}