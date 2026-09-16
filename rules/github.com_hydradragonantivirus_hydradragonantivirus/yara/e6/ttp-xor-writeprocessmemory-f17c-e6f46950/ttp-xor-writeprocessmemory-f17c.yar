rule TTP_XOR_WriteProcessMemory_f17c {
  strings:
    $key_f17c = { a6 0e [2] 94 2c [2] 92 19 [2] bc 19 [2] 83 05 }

  condition:
    any of them
}