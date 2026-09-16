rule TTP_XOR_WriteProcessMemory_a5eb {
  strings:
    $key_a5eb = { f2 99 [2] c0 bb [2] c6 8e [2] e8 8e [2] d7 92 }

  condition:
    any of them
}