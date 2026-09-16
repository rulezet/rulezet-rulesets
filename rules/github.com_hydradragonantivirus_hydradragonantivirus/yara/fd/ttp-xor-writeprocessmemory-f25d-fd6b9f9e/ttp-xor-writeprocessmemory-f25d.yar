rule TTP_XOR_WriteProcessMemory_f25d {
  strings:
    $key_f25d = { a5 2f [2] 97 0d [2] 91 38 [2] bf 38 [2] 80 24 }

  condition:
    any of them
}