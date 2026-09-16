rule TTP_XOR_WriteProcessMemory_f7f0 {
  strings:
    $key_f7f0 = { a0 82 [2] 92 a0 [2] 94 95 [2] ba 95 [2] 85 89 }

  condition:
    any of them
}