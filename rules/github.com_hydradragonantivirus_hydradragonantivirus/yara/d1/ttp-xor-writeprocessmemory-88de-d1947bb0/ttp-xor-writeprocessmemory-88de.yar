rule TTP_XOR_WriteProcessMemory_88de {
  strings:
    $key_88de = { df ac [2] ed 8e [2] eb bb [2] c5 bb [2] fa a7 }

  condition:
    any of them
}