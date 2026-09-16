rule TTP_XOR_WriteProcessMemory_d5de {
  strings:
    $key_d5de = { 82 ac [2] b0 8e [2] b6 bb [2] 98 bb [2] a7 a7 }

  condition:
    any of them
}