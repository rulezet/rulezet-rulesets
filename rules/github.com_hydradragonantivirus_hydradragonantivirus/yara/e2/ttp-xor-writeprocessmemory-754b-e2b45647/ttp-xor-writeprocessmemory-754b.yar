rule TTP_XOR_WriteProcessMemory_754b {
  strings:
    $key_754b = { 22 39 [2] 10 1b [2] 16 2e [2] 38 2e [2] 07 32 }

  condition:
    any of them
}