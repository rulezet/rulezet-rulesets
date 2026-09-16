rule TTP_XOR_WriteProcessMemory_77de {
  strings:
    $key_77de = { 20 ac [2] 12 8e [2] 14 bb [2] 3a bb [2] 05 a7 }

  condition:
    any of them
}