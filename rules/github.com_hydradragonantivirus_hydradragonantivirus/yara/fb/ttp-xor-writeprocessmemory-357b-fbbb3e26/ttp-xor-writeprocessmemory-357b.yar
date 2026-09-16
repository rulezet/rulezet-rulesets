rule TTP_XOR_WriteProcessMemory_357b {
  strings:
    $key_357b = { 62 09 [2] 50 2b [2] 56 1e [2] 78 1e [2] 47 02 }

  condition:
    any of them
}