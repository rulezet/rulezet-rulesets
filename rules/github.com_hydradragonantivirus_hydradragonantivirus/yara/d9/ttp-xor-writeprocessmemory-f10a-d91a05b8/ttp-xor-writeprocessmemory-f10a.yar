rule TTP_XOR_WriteProcessMemory_f10a {
  strings:
    $key_f10a = { a6 78 [2] 94 5a [2] 92 6f [2] bc 6f [2] 83 73 }

  condition:
    any of them
}