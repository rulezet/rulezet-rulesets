rule TTP_XOR_WriteProcessMemory_256b {
  strings:
    $key_256b = { 72 19 [2] 40 3b [2] 46 0e [2] 68 0e [2] 57 12 }

  condition:
    any of them
}