rule TTP_XOR_WriteProcessMemory_f23e {
  strings:
    $key_f23e = { a5 4c [2] 97 6e [2] 91 5b [2] bf 5b [2] 80 47 }

  condition:
    any of them
}