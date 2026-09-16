rule TTP_XOR_WriteProcessMemory_25eb {
  strings:
    $key_25eb = { 72 99 [2] 40 bb [2] 46 8e [2] 68 8e [2] 57 92 }

  condition:
    any of them
}