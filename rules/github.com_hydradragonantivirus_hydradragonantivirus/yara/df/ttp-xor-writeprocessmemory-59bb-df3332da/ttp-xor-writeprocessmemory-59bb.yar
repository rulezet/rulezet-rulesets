rule TTP_XOR_WriteProcessMemory_59bb {
  strings:
    $key_59bb = { 0e c9 [2] 3c eb [2] 3a de [2] 14 de [2] 2b c2 }

  condition:
    any of them
}