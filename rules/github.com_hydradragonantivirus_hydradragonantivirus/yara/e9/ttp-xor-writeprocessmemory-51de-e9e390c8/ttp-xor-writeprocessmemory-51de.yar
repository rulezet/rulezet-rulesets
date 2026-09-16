rule TTP_XOR_WriteProcessMemory_51de {
  strings:
    $key_51de = { 06 ac [2] 34 8e [2] 32 bb [2] 1c bb [2] 23 a7 }

  condition:
    any of them
}