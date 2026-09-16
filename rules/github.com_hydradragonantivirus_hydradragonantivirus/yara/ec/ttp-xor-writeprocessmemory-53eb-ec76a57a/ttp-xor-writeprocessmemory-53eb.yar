rule TTP_XOR_WriteProcessMemory_53eb {
  strings:
    $key_53eb = { 04 99 [2] 36 bb [2] 30 8e [2] 1e 8e [2] 21 92 }

  condition:
    any of them
}