rule TTP_XOR_WriteProcessMemory_f167 {
  strings:
    $key_f167 = { a6 15 [2] 94 37 [2] 92 02 [2] bc 02 [2] 83 1e }

  condition:
    any of them
}