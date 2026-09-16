rule TTP_XOR_WriteProcessMemory_0a9b {
  strings:
    $key_0a9b = { 5d e9 [2] 6f cb [2] 69 fe [2] 47 fe [2] 78 e2 }

  condition:
    any of them
}