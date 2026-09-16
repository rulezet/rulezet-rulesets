rule TTP_XOR_WriteProcessMemory_f2a7 {
  strings:
    $key_f2a7 = { a5 d5 [2] 97 f7 [2] 91 c2 [2] bf c2 [2] 80 de }

  condition:
    any of them
}