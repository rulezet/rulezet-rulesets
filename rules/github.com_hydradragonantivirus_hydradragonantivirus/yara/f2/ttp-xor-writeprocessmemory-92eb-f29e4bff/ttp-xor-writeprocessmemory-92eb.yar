rule TTP_XOR_WriteProcessMemory_92eb {
  strings:
    $key_92eb = { c5 99 [2] f7 bb [2] f1 8e [2] df 8e [2] e0 92 }

  condition:
    any of them
}