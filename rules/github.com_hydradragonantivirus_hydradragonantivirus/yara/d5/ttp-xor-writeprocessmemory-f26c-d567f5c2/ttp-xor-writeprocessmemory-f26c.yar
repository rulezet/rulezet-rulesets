rule TTP_XOR_WriteProcessMemory_f26c {
  strings:
    $key_f26c = { a5 1e [2] 97 3c [2] 91 09 [2] bf 09 [2] 80 15 }

  condition:
    any of them
}