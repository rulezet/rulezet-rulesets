rule TTP_XOR_WriteProcessMemory_f25c {
  strings:
    $key_f25c = { a5 2e [2] 97 0c [2] 91 39 [2] bf 39 [2] 80 25 }

  condition:
    any of them
}