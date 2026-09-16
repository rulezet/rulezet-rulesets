rule TTP_XOR_WriteProcessMemory_f6eb {
  strings:
    $key_f6eb = { a1 99 [2] 93 bb [2] 95 8e [2] bb 8e [2] 84 92 }

  condition:
    any of them
}