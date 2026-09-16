rule TTP_XOR_WriteProcessMemory_02de {
  strings:
    $key_02de = { 55 ac [2] 67 8e [2] 61 bb [2] 4f bb [2] 70 a7 }

  condition:
    any of them
}