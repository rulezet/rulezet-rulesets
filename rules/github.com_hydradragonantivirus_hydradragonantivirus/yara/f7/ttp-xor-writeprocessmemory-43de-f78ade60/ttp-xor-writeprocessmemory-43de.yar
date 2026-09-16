rule TTP_XOR_WriteProcessMemory_43de {
  strings:
    $key_43de = { 14 ac [2] 26 8e [2] 20 bb [2] 0e bb [2] 31 a7 }

  condition:
    any of them
}