rule TTP_XOR_WriteProcessMemory_f17e {
  strings:
    $key_f17e = { a6 0c [2] 94 2e [2] 92 1b [2] bc 1b [2] 83 07 }

  condition:
    any of them
}