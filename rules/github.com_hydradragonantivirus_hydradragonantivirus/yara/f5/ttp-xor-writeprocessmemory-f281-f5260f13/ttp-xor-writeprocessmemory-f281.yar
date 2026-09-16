rule TTP_XOR_WriteProcessMemory_f281 {
  strings:
    $key_f281 = { a5 f3 [2] 97 d1 [2] 91 e4 [2] bf e4 [2] 80 f8 }

  condition:
    any of them
}