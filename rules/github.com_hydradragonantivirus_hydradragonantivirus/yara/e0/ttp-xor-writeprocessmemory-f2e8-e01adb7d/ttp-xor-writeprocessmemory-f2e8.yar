rule TTP_XOR_WriteProcessMemory_f2e8 {
  strings:
    $key_f2e8 = { a5 9a [2] 97 b8 [2] 91 8d [2] bf 8d [2] 80 91 }

  condition:
    any of them
}