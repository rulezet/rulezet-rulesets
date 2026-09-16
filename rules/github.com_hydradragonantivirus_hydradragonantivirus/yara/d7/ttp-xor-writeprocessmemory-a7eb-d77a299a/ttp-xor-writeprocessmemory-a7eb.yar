rule TTP_XOR_WriteProcessMemory_a7eb {
  strings:
    $key_a7eb = { f0 99 [2] c2 bb [2] c4 8e [2] ea 8e [2] d5 92 }

  condition:
    any of them
}