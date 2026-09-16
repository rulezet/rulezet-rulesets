rule TTP_XOR_WriteProcessMemory_f241 {
  strings:
    $key_f241 = { a5 33 [2] 97 11 [2] 91 24 [2] bf 24 [2] 80 38 }

  condition:
    any of them
}