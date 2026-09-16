rule TTP_XOR_WriteProcessMemory_f14b {
  strings:
    $key_f14b = { a6 39 [2] 94 1b [2] 92 2e [2] bc 2e [2] 83 32 }

  condition:
    any of them
}