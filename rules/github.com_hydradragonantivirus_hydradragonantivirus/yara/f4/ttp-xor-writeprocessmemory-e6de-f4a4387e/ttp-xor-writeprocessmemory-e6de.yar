rule TTP_XOR_WriteProcessMemory_e6de {
  strings:
    $key_e6de = { b1 ac [2] 83 8e [2] 85 bb [2] ab bb [2] 94 a7 }

  condition:
    any of them
}