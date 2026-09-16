rule TTP_XOR_WriteProcessMemory_25de {
  strings:
    $key_25de = { 72 ac [2] 40 8e [2] 46 bb [2] 68 bb [2] 57 a7 }

  condition:
    any of them
}