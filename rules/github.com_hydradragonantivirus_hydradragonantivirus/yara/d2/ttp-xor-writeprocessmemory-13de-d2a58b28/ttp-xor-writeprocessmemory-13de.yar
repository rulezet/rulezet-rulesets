rule TTP_XOR_WriteProcessMemory_13de {
  strings:
    $key_13de = { 44 ac [2] 76 8e [2] 70 bb [2] 5e bb [2] 61 a7 }

  condition:
    any of them
}