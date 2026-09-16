rule TTP_XOR_WriteProcessMemory_f5eb {
  strings:
    $key_f5eb = { a2 99 [2] 90 bb [2] 96 8e [2] b8 8e [2] 87 92 }

  condition:
    any of them
}