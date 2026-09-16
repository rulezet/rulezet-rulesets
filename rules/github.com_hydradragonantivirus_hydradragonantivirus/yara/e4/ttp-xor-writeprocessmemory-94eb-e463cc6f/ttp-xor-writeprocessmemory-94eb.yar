rule TTP_XOR_WriteProcessMemory_94eb {
  strings:
    $key_94eb = { c3 99 [2] f1 bb [2] f7 8e [2] d9 8e [2] e6 92 }

  condition:
    any of them
}