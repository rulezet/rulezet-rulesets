rule TTP_XOR_WriteProcessMemory_f094 {
  strings:
    $key_f094 = { a7 e6 [2] 95 c4 [2] 93 f1 [2] bd f1 [2] 82 ed }

  condition:
    any of them
}