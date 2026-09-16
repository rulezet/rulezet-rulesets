rule TTP_XOR_WriteProcessMemory_f11b {
  strings:
    $key_f11b = { a6 69 [2] 94 4b [2] 92 7e [2] bc 7e [2] 83 62 }

  condition:
    any of them
}