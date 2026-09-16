rule TTP_XOR_WriteProcessMemory_f13e {
  strings:
    $key_f13e = { a6 4c [2] 94 6e [2] 92 5b [2] bc 5b [2] 83 47 }

  condition:
    any of them
}