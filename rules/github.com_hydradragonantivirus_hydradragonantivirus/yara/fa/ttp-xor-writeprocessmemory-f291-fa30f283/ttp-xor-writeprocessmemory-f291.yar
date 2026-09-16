rule TTP_XOR_WriteProcessMemory_f291 {
  strings:
    $key_f291 = { a5 e3 [2] 97 c1 [2] 91 f4 [2] bf f4 [2] 80 e8 }

  condition:
    any of them
}