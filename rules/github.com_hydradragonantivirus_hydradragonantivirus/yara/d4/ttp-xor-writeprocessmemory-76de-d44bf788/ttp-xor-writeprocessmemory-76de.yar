rule TTP_XOR_WriteProcessMemory_76de {
  strings:
    $key_76de = { 21 ac [2] 13 8e [2] 15 bb [2] 3b bb [2] 04 a7 }

  condition:
    any of them
}