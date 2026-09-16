rule TTP_XOR_WriteProcessMemory_c1de {
  strings:
    $key_c1de = { 96 ac [2] a4 8e [2] a2 bb [2] 8c bb [2] b3 a7 }

  condition:
    any of them
}