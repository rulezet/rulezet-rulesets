rule TTP_XOR_WriteProcessMemory_2ffc {
  strings:
    $key_2ffc = { 78 8e [2] 4a ac [2] 4c 99 [2] 62 99 [2] 5d 85 }

  condition:
    any of them
}