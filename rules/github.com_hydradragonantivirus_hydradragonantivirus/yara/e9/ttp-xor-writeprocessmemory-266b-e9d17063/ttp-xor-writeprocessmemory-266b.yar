rule TTP_XOR_WriteProcessMemory_266b {
  strings:
    $key_266b = { 71 19 [2] 43 3b [2] 45 0e [2] 6b 0e [2] 54 12 }

  condition:
    any of them
}