rule TTP_XOR_WriteProcessMemory_9dde {
  strings:
    $key_9dde = { ca ac [2] f8 8e [2] fe bb [2] d0 bb [2] ef a7 }

  condition:
    any of them
}