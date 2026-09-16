rule TTP_XOR_WriteProcessMemory_f1f4 {
  strings:
    $key_f1f4 = { a6 86 [2] 94 a4 [2] 92 91 [2] bc 91 [2] 83 8d }

  condition:
    any of them
}