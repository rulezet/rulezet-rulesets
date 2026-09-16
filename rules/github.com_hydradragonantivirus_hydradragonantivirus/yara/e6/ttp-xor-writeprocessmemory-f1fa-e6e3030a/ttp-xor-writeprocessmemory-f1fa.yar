rule TTP_XOR_WriteProcessMemory_f1fa {
  strings:
    $key_f1fa = { a6 88 [2] 94 aa [2] 92 9f [2] bc 9f [2] 83 83 }

  condition:
    any of them
}