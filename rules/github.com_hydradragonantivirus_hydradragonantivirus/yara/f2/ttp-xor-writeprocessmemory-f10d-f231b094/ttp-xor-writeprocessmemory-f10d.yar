rule TTP_XOR_WriteProcessMemory_f10d {
  strings:
    $key_f10d = { a6 7f [2] 94 5d [2] 92 68 [2] bc 68 [2] 83 74 }

  condition:
    any of them
}