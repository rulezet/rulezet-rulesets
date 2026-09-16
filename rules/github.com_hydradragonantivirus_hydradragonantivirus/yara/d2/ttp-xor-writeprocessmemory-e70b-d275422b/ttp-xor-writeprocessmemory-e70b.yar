rule TTP_XOR_WriteProcessMemory_e70b {
  strings:
    $key_e70b = { b0 79 [2] 82 5b [2] 84 6e [2] aa 6e [2] 95 72 }

  condition:
    any of them
}