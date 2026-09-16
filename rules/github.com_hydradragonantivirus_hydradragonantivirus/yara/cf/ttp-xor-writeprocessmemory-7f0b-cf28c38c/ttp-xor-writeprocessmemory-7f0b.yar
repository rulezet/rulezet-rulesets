rule TTP_XOR_WriteProcessMemory_7f0b {
  strings:
    $key_7f0b = { 28 79 [2] 1a 5b [2] 1c 6e [2] 32 6e [2] 0d 72 }

  condition:
    any of them
}