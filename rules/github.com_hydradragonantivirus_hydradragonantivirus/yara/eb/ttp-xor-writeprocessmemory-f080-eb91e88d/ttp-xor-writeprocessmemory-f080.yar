rule TTP_XOR_WriteProcessMemory_f080 {
  strings:
    $key_f080 = { a7 f2 [2] 95 d0 [2] 93 e5 [2] bd e5 [2] 82 f9 }

  condition:
    any of them
}