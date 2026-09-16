rule TTP_XOR_WriteProcessMemory_f210 {
  strings:
    $key_f210 = { a5 62 [2] 97 40 [2] 91 75 [2] bf 75 [2] 80 69 }

  condition:
    any of them
}