rule TTP_XOR_WriteProcessMemory_f2f7 {
  strings:
    $key_f2f7 = { a5 85 [2] 97 a7 [2] 91 92 [2] bf 92 [2] 80 8e }

  condition:
    any of them
}