rule TTP_XOR_WriteProcessMemory_f108 {
  strings:
    $key_f108 = { a6 7a [2] 94 58 [2] 92 6d [2] bc 6d [2] 83 71 }

  condition:
    any of them
}