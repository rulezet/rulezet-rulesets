rule TTP_XOR_WriteProcessMemory_710b {
  strings:
    $key_710b = { 26 79 [2] 14 5b [2] 12 6e [2] 3c 6e [2] 03 72 }

  condition:
    any of them
}