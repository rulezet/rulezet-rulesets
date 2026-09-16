rule TTP_XOR_WriteProcessMemory_b6de {
  strings:
    $key_b6de = { e1 ac [2] d3 8e [2] d5 bb [2] fb bb [2] c4 a7 }

  condition:
    any of them
}