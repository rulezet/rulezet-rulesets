rule TTP_XOR_WriteProcessMemory_f04b {
  strings:
    $key_f04b = { a7 39 [2] 95 1b [2] 93 2e [2] bd 2e [2] 82 32 }

  condition:
    any of them
}