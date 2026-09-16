rule TTP_XOR_WriteProcessMemory_414b {
  strings:
    $key_414b = { 16 39 [2] 24 1b [2] 22 2e [2] 0c 2e [2] 33 32 }

  condition:
    any of them
}