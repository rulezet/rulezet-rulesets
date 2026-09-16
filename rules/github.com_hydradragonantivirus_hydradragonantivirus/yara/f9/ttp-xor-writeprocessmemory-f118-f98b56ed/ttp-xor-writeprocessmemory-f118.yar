rule TTP_XOR_WriteProcessMemory_f118 {
  strings:
    $key_f118 = { a6 6a [2] 94 48 [2] 92 7d [2] bc 7d [2] 83 61 }

  condition:
    any of them
}