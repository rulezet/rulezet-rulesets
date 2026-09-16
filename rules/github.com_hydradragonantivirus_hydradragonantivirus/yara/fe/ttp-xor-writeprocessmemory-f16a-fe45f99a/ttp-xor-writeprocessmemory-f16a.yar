rule TTP_XOR_WriteProcessMemory_f16a {
  strings:
    $key_f16a = { a6 18 [2] 94 3a [2] 92 0f [2] bc 0f [2] 83 13 }

  condition:
    any of them
}