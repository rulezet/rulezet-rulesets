rule TTP_XOR_WriteProcessMemory_b37e {
  strings:
    $key_b37e = { e4 0c [2] d6 2e [2] d0 1b [2] fe 1b [2] c1 07 }

  condition:
    any of them
}