rule TTP_XOR_WriteProcessMemory_f6de {
  strings:
    $key_f6de = { a1 ac [2] 93 8e [2] 95 bb [2] bb bb [2] 84 a7 }

  condition:
    any of them
}