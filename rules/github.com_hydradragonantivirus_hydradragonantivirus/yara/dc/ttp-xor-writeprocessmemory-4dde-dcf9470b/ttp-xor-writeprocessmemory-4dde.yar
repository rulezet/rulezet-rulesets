rule TTP_XOR_WriteProcessMemory_4dde {
  strings:
    $key_4dde = { 1a ac [2] 28 8e [2] 2e bb [2] 00 bb [2] 3f a7 }

  condition:
    any of them
}