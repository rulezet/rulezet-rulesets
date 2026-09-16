rule TTP_XOR_WriteProcessMemory_f10f {
  strings:
    $key_f10f = { a6 7d [2] 94 5f [2] 92 6a [2] bc 6a [2] 83 76 }

  condition:
    any of them
}