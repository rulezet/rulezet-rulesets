rule TTP_XOR_WriteProcessMemory_a9de {
  strings:
    $key_a9de = { fe ac [2] cc 8e [2] ca bb [2] e4 bb [2] db a7 }

  condition:
    any of them
}