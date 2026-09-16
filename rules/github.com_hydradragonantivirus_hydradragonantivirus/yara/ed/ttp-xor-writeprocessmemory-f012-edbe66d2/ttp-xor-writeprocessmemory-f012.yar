rule TTP_XOR_WriteProcessMemory_f012 {
  strings:
    $key_f012 = { a7 60 [2] 95 42 [2] 93 77 [2] bd 77 [2] 82 6b }

  condition:
    any of them
}