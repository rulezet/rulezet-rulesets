rule TTP_XOR_WriteProcessMemory_91de {
  strings:
    $key_91de = { c6 ac [2] f4 8e [2] f2 bb [2] dc bb [2] e3 a7 }

  condition:
    any of them
}