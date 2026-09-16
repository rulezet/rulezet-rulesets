rule TTP_XOR_WriteProcessMemory_f097 {
  strings:
    $key_f097 = { a7 e5 [2] 95 c7 [2] 93 f2 [2] bd f2 [2] 82 ee }

  condition:
    any of them
}