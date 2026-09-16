rule TTP_XOR_WriteProcessMemory_f242 {
  strings:
    $key_f242 = { a5 30 [2] 97 12 [2] 91 27 [2] bf 27 [2] 80 3b }

  condition:
    any of them
}