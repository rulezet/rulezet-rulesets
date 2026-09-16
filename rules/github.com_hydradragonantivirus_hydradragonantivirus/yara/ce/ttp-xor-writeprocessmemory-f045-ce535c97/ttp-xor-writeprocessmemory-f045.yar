rule TTP_XOR_WriteProcessMemory_f045 {
  strings:
    $key_f045 = { a7 37 [2] 95 15 [2] 93 20 [2] bd 20 [2] 82 3c }

  condition:
    any of them
}