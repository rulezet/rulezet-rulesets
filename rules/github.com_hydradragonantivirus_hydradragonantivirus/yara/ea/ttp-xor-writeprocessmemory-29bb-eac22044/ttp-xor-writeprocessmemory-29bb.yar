rule TTP_XOR_WriteProcessMemory_29bb {
  strings:
    $key_29bb = { 7e c9 [2] 4c eb [2] 4a de [2] 64 de [2] 5b c2 }

  condition:
    any of them
}