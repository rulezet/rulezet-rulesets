rule TTP_XOR_WriteProcessMemory_31de {
  strings:
    $key_31de = { 66 ac [2] 54 8e [2] 52 bb [2] 7c bb [2] 43 a7 }

  condition:
    any of them
}