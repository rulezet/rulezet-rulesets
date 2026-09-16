rule TTP_XOR_WriteProcessMemory_b1de {
  strings:
    $key_b1de = { e6 ac [2] d4 8e [2] d2 bb [2] fc bb [2] c3 a7 }

  condition:
    any of them
}