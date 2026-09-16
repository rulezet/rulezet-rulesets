rule TTP_XOR_WriteProcessMemory_f11c {
  strings:
    $key_f11c = { a6 6e [2] 94 4c [2] 92 79 [2] bc 79 [2] 83 65 }

  condition:
    any of them
}