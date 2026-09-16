rule TTP_XOR_WriteProcessMemory_1fde {
  strings:
    $key_1fde = { 48 ac [2] 7a 8e [2] 7c bb [2] 52 bb [2] 6d a7 }

  condition:
    any of them
}