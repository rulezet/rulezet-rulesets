rule TTP_XOR_WriteProcessMemory_f73b {
  strings:
    $key_f73b = { a0 49 [2] 92 6b [2] 94 5e [2] ba 5e [2] 85 42 }

  condition:
    any of them
}