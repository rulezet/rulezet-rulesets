rule TTP_XOR_WriteProcessMemory_336b {
  strings:
    $key_336b = { 64 19 [2] 56 3b [2] 50 0e [2] 7e 0e [2] 41 12 }

  condition:
    any of them
}