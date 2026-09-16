rule TTP_XOR_WriteProcessMemory_f2db {
  strings:
    $key_f2db = { a5 a9 [2] 97 8b [2] 91 be [2] bf be [2] 80 a2 }

  condition:
    any of them
}