rule TTP_XOR_WriteProcessMemory_90eb {
  strings:
    $key_90eb = { c7 99 [2] f5 bb [2] f3 8e [2] dd 8e [2] e2 92 }

  condition:
    any of them
}