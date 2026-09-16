rule TTP_XOR_WriteProcessMemory_6f6b {
  strings:
    $key_6f6b = { 38 19 [2] 0a 3b [2] 0c 0e [2] 22 0e [2] 1d 12 }

  condition:
    any of them
}