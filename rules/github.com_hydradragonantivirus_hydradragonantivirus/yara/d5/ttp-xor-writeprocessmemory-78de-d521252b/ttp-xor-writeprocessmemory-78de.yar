rule TTP_XOR_WriteProcessMemory_78de {
  strings:
    $key_78de = { 2f ac [2] 1d 8e [2] 1b bb [2] 35 bb [2] 0a a7 }

  condition:
    any of them
}