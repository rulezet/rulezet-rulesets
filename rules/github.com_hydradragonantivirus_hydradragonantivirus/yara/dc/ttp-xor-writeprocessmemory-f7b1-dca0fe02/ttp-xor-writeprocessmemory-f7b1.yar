rule TTP_XOR_WriteProcessMemory_f7b1 {
  strings:
    $key_f7b1 = { a0 c3 [2] 92 e1 [2] 94 d4 [2] ba d4 [2] 85 c8 }

  condition:
    any of them
}