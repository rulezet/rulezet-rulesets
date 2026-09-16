rule TTP_XOR_WriteProcessMemory_23de {
  strings:
    $key_23de = { 74 ac [2] 46 8e [2] 40 bb [2] 6e bb [2] 51 a7 }

  condition:
    any of them
}