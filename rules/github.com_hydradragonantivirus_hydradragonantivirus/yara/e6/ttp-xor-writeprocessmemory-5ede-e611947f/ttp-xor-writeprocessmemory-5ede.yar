rule TTP_XOR_WriteProcessMemory_5ede {
  strings:
    $key_5ede = { 09 ac [2] 3b 8e [2] 3d bb [2] 13 bb [2] 2c a7 }

  condition:
    any of them
}