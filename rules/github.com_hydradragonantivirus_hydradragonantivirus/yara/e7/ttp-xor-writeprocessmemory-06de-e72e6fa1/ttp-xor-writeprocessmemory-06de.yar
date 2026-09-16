rule TTP_XOR_WriteProcessMemory_06de {
  strings:
    $key_06de = { 51 ac [2] 63 8e [2] 65 bb [2] 4b bb [2] 74 a7 }

  condition:
    any of them
}