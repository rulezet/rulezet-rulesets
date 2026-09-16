rule TTP_XOR_WriteProcessMemory_e73b {
  strings:
    $key_e73b = { b0 49 [2] 82 6b [2] 84 5e [2] aa 5e [2] 95 42 }

  condition:
    any of them
}