rule TTP_XOR_WriteProcessMemory_b6eb {
  strings:
    $key_b6eb = { e1 99 [2] d3 bb [2] d5 8e [2] fb 8e [2] c4 92 }

  condition:
    any of them
}