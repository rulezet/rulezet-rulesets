rule TTP_XOR_WriteProcessMemory_7bfc {
  strings:
    $key_7bfc = { 2c 8e [2] 1e ac [2] 18 99 [2] 36 99 [2] 09 85 }

  condition:
    any of them
}