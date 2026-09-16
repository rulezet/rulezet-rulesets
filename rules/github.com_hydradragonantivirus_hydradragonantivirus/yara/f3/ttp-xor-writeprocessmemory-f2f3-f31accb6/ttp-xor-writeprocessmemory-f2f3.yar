rule TTP_XOR_WriteProcessMemory_f2f3 {
  strings:
    $key_f2f3 = { a5 81 [2] 97 a3 [2] 91 96 [2] bf 96 [2] 80 8a }

  condition:
    any of them
}