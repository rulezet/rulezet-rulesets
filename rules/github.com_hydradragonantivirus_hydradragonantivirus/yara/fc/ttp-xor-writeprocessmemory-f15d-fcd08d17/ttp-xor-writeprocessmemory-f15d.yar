rule TTP_XOR_WriteProcessMemory_f15d {
  strings:
    $key_f15d = { a6 2f [2] 94 0d [2] 92 38 [2] bc 38 [2] 83 24 }

  condition:
    any of them
}