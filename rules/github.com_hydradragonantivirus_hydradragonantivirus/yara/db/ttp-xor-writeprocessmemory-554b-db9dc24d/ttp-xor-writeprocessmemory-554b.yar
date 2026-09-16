rule TTP_XOR_WriteProcessMemory_554b {
  strings:
    $key_554b = { 02 39 [2] 30 1b [2] 36 2e [2] 18 2e [2] 27 32 }

  condition:
    any of them
}