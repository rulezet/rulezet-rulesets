rule TTP_XOR_WriteProcessMemory_f27b {
  strings:
    $key_f27b = { a5 09 [2] 97 2b [2] 91 1e [2] bf 1e [2] 80 02 }

  condition:
    any of them
}