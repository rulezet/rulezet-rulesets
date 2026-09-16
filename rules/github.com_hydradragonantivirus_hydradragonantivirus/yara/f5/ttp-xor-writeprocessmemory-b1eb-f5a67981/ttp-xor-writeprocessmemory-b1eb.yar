rule TTP_XOR_WriteProcessMemory_b1eb {
  strings:
    $key_b1eb = { e6 99 [2] d4 bb [2] d2 8e [2] fc 8e [2] c3 92 }

  condition:
    any of them
}