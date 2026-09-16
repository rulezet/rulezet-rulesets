rule TTP_XOR_WriteProcessMemory_f22e {
  strings:
    $key_f22e = { a5 5c [2] 97 7e [2] 91 4b [2] bf 4b [2] 80 57 }

  condition:
    any of them
}