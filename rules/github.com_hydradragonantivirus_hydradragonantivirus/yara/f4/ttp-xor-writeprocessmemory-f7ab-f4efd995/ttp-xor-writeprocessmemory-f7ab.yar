rule TTP_XOR_WriteProcessMemory_f7ab {
  strings:
    $key_f7ab = { a0 d9 [2] 92 fb [2] 94 ce [2] ba ce [2] 85 d2 }

  condition:
    any of them
}