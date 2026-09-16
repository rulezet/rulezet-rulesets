rule TTP_XOR_WriteProcessMemory_57eb {
  strings:
    $key_57eb = { 00 99 [2] 32 bb [2] 34 8e [2] 1a 8e [2] 25 92 }

  condition:
    any of them
}