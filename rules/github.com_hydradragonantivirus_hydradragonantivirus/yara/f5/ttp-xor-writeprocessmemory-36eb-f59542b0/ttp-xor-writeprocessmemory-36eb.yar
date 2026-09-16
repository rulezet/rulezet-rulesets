rule TTP_XOR_WriteProcessMemory_36eb {
  strings:
    $key_36eb = { 61 99 [2] 53 bb [2] 55 8e [2] 7b 8e [2] 44 92 }

  condition:
    any of them
}