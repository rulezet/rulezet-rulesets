rule TTP_XOR_WriteProcessMemory_400b {
  strings:
    $key_400b = { 17 79 [2] 25 5b [2] 23 6e [2] 0d 6e [2] 32 72 }

  condition:
    any of them
}