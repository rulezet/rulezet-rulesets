rule TTP_XOR_WriteProcessMemory_474b {
  strings:
    $key_474b = { 10 39 [2] 22 1b [2] 24 2e [2] 0a 2e [2] 35 32 }

  condition:
    any of them
}