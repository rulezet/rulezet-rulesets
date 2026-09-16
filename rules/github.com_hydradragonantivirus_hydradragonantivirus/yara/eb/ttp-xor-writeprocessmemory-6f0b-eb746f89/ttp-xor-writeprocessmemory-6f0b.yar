rule TTP_XOR_WriteProcessMemory_6f0b {
  strings:
    $key_6f0b = { 38 79 [2] 0a 5b [2] 0c 6e [2] 22 6e [2] 1d 72 }

  condition:
    any of them
}