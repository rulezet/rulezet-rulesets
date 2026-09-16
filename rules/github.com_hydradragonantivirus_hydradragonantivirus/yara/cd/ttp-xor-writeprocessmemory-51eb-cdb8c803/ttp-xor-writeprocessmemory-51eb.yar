rule TTP_XOR_WriteProcessMemory_51eb {
  strings:
    $key_51eb = { 06 99 [2] 34 bb [2] 32 8e [2] 1c 8e [2] 23 92 }

  condition:
    any of them
}