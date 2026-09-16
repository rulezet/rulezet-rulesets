rule TTP_XOR_WriteProcessMemory_07eb {
  strings:
    $key_07eb = { 50 99 [2] 62 bb [2] 64 8e [2] 4a 8e [2] 75 92 }

  condition:
    any of them
}