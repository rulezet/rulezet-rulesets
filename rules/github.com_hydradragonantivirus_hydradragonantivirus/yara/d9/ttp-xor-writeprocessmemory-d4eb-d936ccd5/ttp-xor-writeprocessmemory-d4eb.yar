rule TTP_XOR_WriteProcessMemory_d4eb {
  strings:
    $key_d4eb = { 83 99 [2] b1 bb [2] b7 8e [2] 99 8e [2] a6 92 }

  condition:
    any of them
}