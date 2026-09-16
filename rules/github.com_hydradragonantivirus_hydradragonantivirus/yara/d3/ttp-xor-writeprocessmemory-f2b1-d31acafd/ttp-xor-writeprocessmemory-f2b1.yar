rule TTP_XOR_WriteProcessMemory_f2b1 {
  strings:
    $key_f2b1 = { a5 c3 [2] 97 e1 [2] 91 d4 [2] bf d4 [2] 80 c8 }

  condition:
    any of them
}