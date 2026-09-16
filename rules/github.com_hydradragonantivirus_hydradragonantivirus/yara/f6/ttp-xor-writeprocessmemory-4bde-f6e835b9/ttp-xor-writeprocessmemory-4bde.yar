rule TTP_XOR_WriteProcessMemory_4bde {
  strings:
    $key_4bde = { 1c ac [2] 2e 8e [2] 28 bb [2] 06 bb [2] 39 a7 }

  condition:
    any of them
}