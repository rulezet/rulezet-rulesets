rule TTP_XOR_WriteProcessMemory_f780 {
  strings:
    $key_f780 = { a0 f2 [2] 92 d0 [2] 94 e5 [2] ba e5 [2] 85 f9 }

  condition:
    any of them
}