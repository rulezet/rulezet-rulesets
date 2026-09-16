rule TTP_XOR_WriteProcessMemory_f2d6 {
  strings:
    $key_f2d6 = { a5 a4 [2] 97 86 [2] 91 b3 [2] bf b3 [2] 80 af }

  condition:
    any of them
}