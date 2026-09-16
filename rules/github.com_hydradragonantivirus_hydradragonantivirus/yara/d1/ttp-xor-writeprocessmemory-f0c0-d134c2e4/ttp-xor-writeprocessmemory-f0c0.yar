rule TTP_XOR_WriteProcessMemory_f0c0 {
  strings:
    $key_f0c0 = { a7 b2 [2] 95 90 [2] 93 a5 [2] bd a5 [2] 82 b9 }

  condition:
    any of them
}