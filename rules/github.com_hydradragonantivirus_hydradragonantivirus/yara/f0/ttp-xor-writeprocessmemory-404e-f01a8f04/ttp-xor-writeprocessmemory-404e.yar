rule TTP_XOR_WriteProcessMemory_404e {
  strings:
    $key_404e = { 17 3c [2] 25 1e [2] 23 2b [2] 0d 2b [2] 32 37 }

  condition:
    any of them
}