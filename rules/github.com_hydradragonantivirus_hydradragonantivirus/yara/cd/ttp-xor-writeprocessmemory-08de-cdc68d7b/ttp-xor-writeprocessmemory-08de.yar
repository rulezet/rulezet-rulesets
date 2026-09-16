rule TTP_XOR_WriteProcessMemory_08de {
  strings:
    $key_08de = { 5f ac [2] 6d 8e [2] 6b bb [2] 45 bb [2] 7a a7 }

  condition:
    any of them
}