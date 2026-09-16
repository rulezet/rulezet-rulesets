rule TTP_XOR_WriteProcessMemory_336c {
  strings:
    $key_336c = { 64 1e [2] 56 3c [2] 50 09 [2] 7e 09 [2] 41 15 }

  condition:
    any of them
}