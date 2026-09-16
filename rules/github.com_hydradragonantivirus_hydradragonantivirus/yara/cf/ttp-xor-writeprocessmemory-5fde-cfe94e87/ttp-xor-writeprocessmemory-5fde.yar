rule TTP_XOR_WriteProcessMemory_5fde {
  strings:
    $key_5fde = { 08 ac [2] 3a 8e [2] 3c bb [2] 12 bb [2] 2d a7 }

  condition:
    any of them
}