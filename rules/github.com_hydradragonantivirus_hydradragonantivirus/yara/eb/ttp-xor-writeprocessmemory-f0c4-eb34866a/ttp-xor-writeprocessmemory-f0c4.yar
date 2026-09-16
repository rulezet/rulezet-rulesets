rule TTP_XOR_WriteProcessMemory_f0c4 {
  strings:
    $key_f0c4 = { a7 b6 [2] 95 94 [2] 93 a1 [2] bd a1 [2] 82 bd }

  condition:
    any of them
}