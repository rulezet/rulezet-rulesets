rule TTP_XOR_WriteProcessMemory_f2c1 {
  strings:
    $key_f2c1 = { a5 b3 [2] 97 91 [2] 91 a4 [2] bf a4 [2] 80 b8 }

  condition:
    any of them
}