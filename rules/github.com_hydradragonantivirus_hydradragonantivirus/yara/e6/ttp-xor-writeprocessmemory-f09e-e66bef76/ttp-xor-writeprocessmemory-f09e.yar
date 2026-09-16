rule TTP_XOR_WriteProcessMemory_f09e {
  strings:
    $key_f09e = { a7 ec [2] 95 ce [2] 93 fb [2] bd fb [2] 82 e7 }

  condition:
    any of them
}