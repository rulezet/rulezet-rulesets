rule TTP_XOR_WriteProcessMemory_f12d {
  strings:
    $key_f12d = { a6 5f [2] 94 7d [2] 92 48 [2] bc 48 [2] 83 54 }

  condition:
    any of them
}