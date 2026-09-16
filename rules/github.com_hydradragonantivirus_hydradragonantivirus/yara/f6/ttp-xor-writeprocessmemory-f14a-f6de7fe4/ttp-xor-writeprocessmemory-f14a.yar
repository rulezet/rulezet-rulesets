rule TTP_XOR_WriteProcessMemory_f14a {
  strings:
    $key_f14a = { a6 38 [2] 94 1a [2] 92 2f [2] bc 2f [2] 83 33 }

  condition:
    any of them
}