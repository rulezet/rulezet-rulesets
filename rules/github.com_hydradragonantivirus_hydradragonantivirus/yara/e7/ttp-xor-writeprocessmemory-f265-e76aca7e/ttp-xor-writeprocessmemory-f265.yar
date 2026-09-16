rule TTP_XOR_WriteProcessMemory_f265 {
  strings:
    $key_f265 = { a5 17 [2] 97 35 [2] 91 00 [2] bf 00 [2] 80 1c }

  condition:
    any of them
}