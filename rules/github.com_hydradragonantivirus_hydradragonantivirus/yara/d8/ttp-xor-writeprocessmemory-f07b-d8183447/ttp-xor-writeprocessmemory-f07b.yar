rule TTP_XOR_WriteProcessMemory_f07b {
  strings:
    $key_f07b = { a7 09 [2] 95 2b [2] 93 1e [2] bd 1e [2] 82 02 }

  condition:
    any of them
}