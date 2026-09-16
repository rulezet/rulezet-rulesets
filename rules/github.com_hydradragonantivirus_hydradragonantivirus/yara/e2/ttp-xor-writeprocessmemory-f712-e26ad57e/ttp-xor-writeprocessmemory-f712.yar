rule TTP_XOR_WriteProcessMemory_f712 {
  strings:
    $key_f712 = { a0 60 [2] 92 42 [2] 94 77 [2] ba 77 [2] 85 6b }

  condition:
    any of them
}