rule TTP_XOR_WriteProcessMemory_f2a1 {
  strings:
    $key_f2a1 = { a5 d3 [2] 97 f1 [2] 91 c4 [2] bf c4 [2] 80 d8 }

  condition:
    any of them
}