rule TTP_XOR_WriteProcessMemory_776b {
  strings:
    $key_776b = { 20 19 [2] 12 3b [2] 14 0e [2] 3a 0e [2] 05 12 }

  condition:
    any of them
}