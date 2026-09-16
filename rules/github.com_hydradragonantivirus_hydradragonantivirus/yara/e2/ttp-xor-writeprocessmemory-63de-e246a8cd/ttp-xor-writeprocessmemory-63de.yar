rule TTP_XOR_WriteProcessMemory_63de {
  strings:
    $key_63de = { 34 ac [2] 06 8e [2] 00 bb [2] 2e bb [2] 11 a7 }

  condition:
    any of them
}