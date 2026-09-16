rule TTP_XOR_WriteProcessMemory_f6bb {
  strings:
    $key_f6bb = { a1 c9 [2] 93 eb [2] 95 de [2] bb de [2] 84 c2 }

  condition:
    any of them
}