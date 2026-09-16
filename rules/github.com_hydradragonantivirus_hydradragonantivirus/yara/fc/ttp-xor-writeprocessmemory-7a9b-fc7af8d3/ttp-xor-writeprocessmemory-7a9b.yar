rule TTP_XOR_WriteProcessMemory_7a9b {
  strings:
    $key_7a9b = { 2d e9 [2] 1f cb [2] 19 fe [2] 37 fe [2] 08 e2 }

  condition:
    any of them
}