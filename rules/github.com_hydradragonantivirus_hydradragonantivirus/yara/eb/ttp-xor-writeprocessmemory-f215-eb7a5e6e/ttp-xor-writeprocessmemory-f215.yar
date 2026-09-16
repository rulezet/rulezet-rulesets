rule TTP_XOR_WriteProcessMemory_f215 {
  strings:
    $key_f215 = { a5 67 [2] 97 45 [2] 91 70 [2] bf 70 [2] 80 6c }

  condition:
    any of them
}