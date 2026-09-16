rule TTP_XOR_WriteProcessMemory_50de {
  strings:
    $key_50de = { 07 ac [2] 35 8e [2] 33 bb [2] 1d bb [2] 22 a7 }

  condition:
    any of them
}