rule TTP_XOR_WriteProcessMemory_d5eb {
  strings:
    $key_d5eb = { 82 99 [2] b0 bb [2] b6 8e [2] 98 8e [2] a7 92 }

  condition:
    any of them
}