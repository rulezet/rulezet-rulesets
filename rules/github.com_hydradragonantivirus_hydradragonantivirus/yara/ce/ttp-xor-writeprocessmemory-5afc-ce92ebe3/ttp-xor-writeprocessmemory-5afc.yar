rule TTP_XOR_WriteProcessMemory_5afc {
  strings:
    $key_5afc = { 0d 8e [2] 3f ac [2] 39 99 [2] 17 99 [2] 28 85 }

  condition:
    any of them
}