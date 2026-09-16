rule TTP_XOR_WriteProcessMemory_f06b {
  strings:
    $key_f06b = { a7 19 [2] 95 3b [2] 93 0e [2] bd 0e [2] 82 12 }

  condition:
    any of them
}