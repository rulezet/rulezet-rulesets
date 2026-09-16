rule TTP_XOR_WriteProcessMemory_70de {
  strings:
    $key_70de = { 27 ac [2] 15 8e [2] 13 bb [2] 3d bb [2] 02 a7 }

  condition:
    any of them
}