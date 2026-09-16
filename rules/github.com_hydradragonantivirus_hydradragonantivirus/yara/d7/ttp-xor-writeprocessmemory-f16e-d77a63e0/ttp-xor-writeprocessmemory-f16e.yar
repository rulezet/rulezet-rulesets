rule TTP_XOR_WriteProcessMemory_f16e {
  strings:
    $key_f16e = { a6 1c [2] 94 3e [2] 92 0b [2] bc 0b [2] 83 17 }

  condition:
    any of them
}