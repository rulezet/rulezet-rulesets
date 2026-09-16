rule TTP_XOR_WriteProcessMemory_c6eb {
  strings:
    $key_c6eb = { 91 99 [2] a3 bb [2] a5 8e [2] 8b 8e [2] b4 92 }

  condition:
    any of them
}