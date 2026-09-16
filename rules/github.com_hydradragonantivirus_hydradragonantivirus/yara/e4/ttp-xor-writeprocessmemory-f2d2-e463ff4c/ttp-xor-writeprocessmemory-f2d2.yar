rule TTP_XOR_WriteProcessMemory_f2d2 {
  strings:
    $key_f2d2 = { a5 a0 [2] 97 82 [2] 91 b7 [2] bf b7 [2] 80 ab }

  condition:
    any of them
}