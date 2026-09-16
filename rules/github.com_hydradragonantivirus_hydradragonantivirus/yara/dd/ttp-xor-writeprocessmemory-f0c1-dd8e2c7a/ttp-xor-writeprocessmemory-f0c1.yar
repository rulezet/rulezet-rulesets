rule TTP_XOR_WriteProcessMemory_f0c1 {
  strings:
    $key_f0c1 = { a7 b3 [2] 95 91 [2] 93 a4 [2] bd a4 [2] 82 b8 }

  condition:
    any of them
}