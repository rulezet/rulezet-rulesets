rule TTP_XOR_WriteProcessMemory_41de {
  strings:
    $key_41de = { 16 ac [2] 24 8e [2] 22 bb [2] 0c bb [2] 33 a7 }

  condition:
    any of them
}