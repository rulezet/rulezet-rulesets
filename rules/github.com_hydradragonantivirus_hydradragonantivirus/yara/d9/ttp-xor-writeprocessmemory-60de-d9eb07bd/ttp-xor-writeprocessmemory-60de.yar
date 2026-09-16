rule TTP_XOR_WriteProcessMemory_60de {
  strings:
    $key_60de = { 37 ac [2] 05 8e [2] 03 bb [2] 2d bb [2] 12 a7 }

  condition:
    any of them
}