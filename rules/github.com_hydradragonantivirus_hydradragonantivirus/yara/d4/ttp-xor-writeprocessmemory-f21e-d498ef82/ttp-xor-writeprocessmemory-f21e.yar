rule TTP_XOR_WriteProcessMemory_f21e {
  strings:
    $key_f21e = { a5 6c [2] 97 4e [2] 91 7b [2] bf 7b [2] 80 67 }

  condition:
    any of them
}