rule TTP_XOR_WriteProcessMemory_f2f6 {
  strings:
    $key_f2f6 = { a5 84 [2] 97 a6 [2] 91 93 [2] bf 93 [2] 80 8f }

  condition:
    any of them
}