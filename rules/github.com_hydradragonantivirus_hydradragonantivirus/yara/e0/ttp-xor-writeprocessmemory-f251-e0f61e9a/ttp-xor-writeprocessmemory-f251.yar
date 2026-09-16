rule TTP_XOR_WriteProcessMemory_f251 {
  strings:
    $key_f251 = { a5 23 [2] 97 01 [2] 91 34 [2] bf 34 [2] 80 28 }

  condition:
    any of them
}