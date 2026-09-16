rule TTP_XOR_WriteProcessMemory_56eb {
  strings:
    $key_56eb = { 01 99 [2] 33 bb [2] 35 8e [2] 1b 8e [2] 24 92 }

  condition:
    any of them
}