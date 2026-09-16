rule TTP_XOR_WriteProcessMemory_f0e0 {
  strings:
    $key_f0e0 = { a7 92 [2] 95 b0 [2] 93 85 [2] bd 85 [2] 82 99 }

  condition:
    any of them
}