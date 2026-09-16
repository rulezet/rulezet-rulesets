rule TTP_XOR_WriteProcessMemory_1e0b {
  strings:
    $key_1e0b = { 49 79 [2] 7b 5b [2] 7d 6e [2] 53 6e [2] 6c 72 }

  condition:
    any of them
}