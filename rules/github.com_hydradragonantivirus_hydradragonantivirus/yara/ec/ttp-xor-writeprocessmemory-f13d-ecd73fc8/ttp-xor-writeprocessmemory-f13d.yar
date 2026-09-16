rule TTP_XOR_WriteProcessMemory_f13d {
  strings:
    $key_f13d = { a6 4f [2] 94 6d [2] 92 58 [2] bc 58 [2] 83 44 }

  condition:
    any of them
}