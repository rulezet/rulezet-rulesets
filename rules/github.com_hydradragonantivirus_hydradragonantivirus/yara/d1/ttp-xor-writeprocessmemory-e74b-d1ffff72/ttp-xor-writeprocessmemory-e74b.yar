rule TTP_XOR_WriteProcessMemory_e74b {
  strings:
    $key_e74b = { b0 39 [2] 82 1b [2] 84 2e [2] aa 2e [2] 95 32 }

  condition:
    any of them
}