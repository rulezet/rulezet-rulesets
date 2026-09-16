rule TTP_XOR_WriteProcessMemory_f15a {
  strings:
    $key_f15a = { a6 28 [2] 94 0a [2] 92 3f [2] bc 3f [2] 83 23 }

  condition:
    any of them
}