rule TTP_XOR_WriteProcessMemory_97eb {
  strings:
    $key_97eb = { c0 99 [2] f2 bb [2] f4 8e [2] da 8e [2] e5 92 }

  condition:
    any of them
}