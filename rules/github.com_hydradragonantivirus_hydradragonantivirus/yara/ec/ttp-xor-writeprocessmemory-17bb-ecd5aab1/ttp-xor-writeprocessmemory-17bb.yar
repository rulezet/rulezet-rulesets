rule TTP_XOR_WriteProcessMemory_17bb {
  strings:
    $key_17bb = { 40 c9 [2] 72 eb [2] 74 de [2] 5a de [2] 65 c2 }

  condition:
    any of them
}