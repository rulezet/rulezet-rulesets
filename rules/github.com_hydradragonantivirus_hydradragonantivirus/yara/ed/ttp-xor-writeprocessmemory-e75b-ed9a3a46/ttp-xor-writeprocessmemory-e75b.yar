rule TTP_XOR_WriteProcessMemory_e75b {
  strings:
    $key_e75b = { b0 29 [2] 82 0b [2] 84 3e [2] aa 3e [2] 95 22 }

  condition:
    any of them
}