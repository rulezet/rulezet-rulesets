rule TTP_XOR_WriteProcessMemory_7efc {
  strings:
    $key_7efc = { 29 8e [2] 1b ac [2] 1d 99 [2] 33 99 [2] 0c 85 }

  condition:
    any of them
}