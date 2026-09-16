rule TTP_XOR_WriteProcessMemory_f5bb {
  strings:
    $key_f5bb = { a2 c9 [2] 90 eb [2] 96 de [2] b8 de [2] 87 c2 }

  condition:
    any of them
}