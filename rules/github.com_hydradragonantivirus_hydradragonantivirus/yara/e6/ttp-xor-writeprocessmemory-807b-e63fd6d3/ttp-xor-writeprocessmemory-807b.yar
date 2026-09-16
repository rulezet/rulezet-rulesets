rule TTP_XOR_WriteProcessMemory_807b {
  strings:
    $key_807b = { d7 09 [2] e5 2b [2] e3 1e [2] cd 1e [2] f2 02 }

  condition:
    any of them
}