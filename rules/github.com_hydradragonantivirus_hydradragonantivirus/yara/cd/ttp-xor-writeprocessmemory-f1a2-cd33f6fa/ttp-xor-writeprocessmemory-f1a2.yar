rule TTP_XOR_WriteProcessMemory_f1a2 {
  strings:
    $key_f1a2 = { a6 d0 [2] 94 f2 [2] 92 c7 [2] bc c7 [2] 83 db }

  condition:
    any of them
}