rule TTP_XOR_WriteProcessMemory_f2a3 {
  strings:
    $key_f2a3 = { a5 d1 [2] 97 f3 [2] 91 c6 [2] bf c6 [2] 80 da }

  condition:
    any of them
}