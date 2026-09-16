rule TTP_XOR_WriteProcessMemory_eceb {
  strings:
    $key_eceb = { bb 99 [2] 89 bb [2] 8f 8e [2] a1 8e [2] 9e 92 }

  condition:
    any of them
}