rule TTP_XOR_WriteProcessMemory_6ffc {
  strings:
    $key_6ffc = { 38 8e [2] 0a ac [2] 0c 99 [2] 22 99 [2] 1d 85 }

  condition:
    any of them
}