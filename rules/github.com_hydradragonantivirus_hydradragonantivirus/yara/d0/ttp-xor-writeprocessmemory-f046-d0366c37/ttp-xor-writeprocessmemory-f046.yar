rule TTP_XOR_WriteProcessMemory_f046 {
  strings:
    $key_f046 = { a7 34 [2] 95 16 [2] 93 23 [2] bd 23 [2] 82 3f }

  condition:
    any of them
}