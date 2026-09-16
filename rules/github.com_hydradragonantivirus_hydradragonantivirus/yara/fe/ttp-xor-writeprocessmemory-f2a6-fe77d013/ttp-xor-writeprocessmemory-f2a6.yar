rule TTP_XOR_WriteProcessMemory_f2a6 {
  strings:
    $key_f2a6 = { a5 d4 [2] 97 f6 [2] 91 c3 [2] bf c3 [2] 80 df }

  condition:
    any of them
}