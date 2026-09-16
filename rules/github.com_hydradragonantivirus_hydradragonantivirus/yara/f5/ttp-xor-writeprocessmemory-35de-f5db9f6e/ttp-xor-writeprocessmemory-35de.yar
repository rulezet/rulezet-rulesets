rule TTP_XOR_WriteProcessMemory_35de {
  strings:
    $key_35de = { 62 ac [2] 50 8e [2] 56 bb [2] 78 bb [2] 47 a7 }

  condition:
    any of them
}