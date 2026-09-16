rule TTP_XOR_WriteProcessMemory_1dde {
  strings:
    $key_1dde = { 4a ac [2] 78 8e [2] 7e bb [2] 50 bb [2] 6f a7 }

  condition:
    any of them
}