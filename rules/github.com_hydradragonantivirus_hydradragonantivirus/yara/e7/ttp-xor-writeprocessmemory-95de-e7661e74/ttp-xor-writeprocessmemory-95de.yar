rule TTP_XOR_WriteProcessMemory_95de {
  strings:
    $key_95de = { c2 ac [2] f0 8e [2] f6 bb [2] d8 bb [2] e7 a7 }

  condition:
    any of them
}