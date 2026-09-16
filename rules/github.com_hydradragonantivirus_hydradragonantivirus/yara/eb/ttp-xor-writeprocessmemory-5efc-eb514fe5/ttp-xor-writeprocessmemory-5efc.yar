rule TTP_XOR_WriteProcessMemory_5efc {
  strings:
    $key_5efc = { 09 8e [2] 3b ac [2] 3d 99 [2] 13 99 [2] 2c 85 }

  condition:
    any of them
}