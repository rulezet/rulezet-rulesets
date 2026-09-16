rule TTP_XOR_WriteProcessMemory_9bde {
  strings:
    $key_9bde = { cc ac [2] fe 8e [2] f8 bb [2] d6 bb [2] e9 a7 }

  condition:
    any of them
}