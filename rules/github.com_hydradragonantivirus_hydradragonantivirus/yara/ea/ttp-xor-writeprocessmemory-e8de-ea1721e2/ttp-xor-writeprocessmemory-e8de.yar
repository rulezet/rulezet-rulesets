rule TTP_XOR_WriteProcessMemory_e8de {
  strings:
    $key_e8de = { bf ac [2] 8d 8e [2] 8b bb [2] a5 bb [2] 9a a7 }

  condition:
    any of them
}