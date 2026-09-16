rule TTP_XOR_WriteProcessMemory_d2de {
  strings:
    $key_d2de = { 85 ac [2] b7 8e [2] b1 bb [2] 9f bb [2] a0 a7 }

  condition:
    any of them
}