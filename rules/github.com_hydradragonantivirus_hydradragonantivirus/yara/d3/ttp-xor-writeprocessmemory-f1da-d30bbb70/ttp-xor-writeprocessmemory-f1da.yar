rule TTP_XOR_WriteProcessMemory_f1da {
  strings:
    $key_f1da = { a6 a8 [2] 94 8a [2] 92 bf [2] bc bf [2] 83 a3 }

  condition:
    any of them
}