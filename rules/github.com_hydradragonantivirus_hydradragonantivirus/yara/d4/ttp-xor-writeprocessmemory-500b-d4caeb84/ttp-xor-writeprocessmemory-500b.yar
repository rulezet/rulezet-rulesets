rule TTP_XOR_WriteProcessMemory_500b {
  strings:
    $key_500b = { 07 79 [2] 35 5b [2] 33 6e [2] 1d 6e [2] 22 72 }

  condition:
    any of them
}