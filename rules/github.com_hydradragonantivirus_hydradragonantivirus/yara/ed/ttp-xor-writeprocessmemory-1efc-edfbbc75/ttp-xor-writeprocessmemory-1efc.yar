rule TTP_XOR_WriteProcessMemory_1efc {
  strings:
    $key_1efc = { 49 8e [2] 7b ac [2] 7d 99 [2] 53 99 [2] 6c 85 }

  condition:
    any of them
}