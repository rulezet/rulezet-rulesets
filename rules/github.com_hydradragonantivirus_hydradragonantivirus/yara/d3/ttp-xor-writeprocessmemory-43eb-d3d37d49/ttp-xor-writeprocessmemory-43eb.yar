rule TTP_XOR_WriteProcessMemory_43eb {
  strings:
    $key_43eb = { 14 99 [2] 26 bb [2] 20 8e [2] 0e 8e [2] 31 92 }

  condition:
    any of them
}