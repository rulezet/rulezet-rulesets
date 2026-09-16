rule TTP_XOR_WriteProcessMemory_f7d1 {
  strings:
    $key_f7d1 = { a0 a3 [2] 92 81 [2] 94 b4 [2] ba b4 [2] 85 a8 }

  condition:
    any of them
}