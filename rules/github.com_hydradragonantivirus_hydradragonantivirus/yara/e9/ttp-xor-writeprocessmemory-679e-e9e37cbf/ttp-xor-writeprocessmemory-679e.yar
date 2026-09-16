rule TTP_XOR_WriteProcessMemory_679e {
  strings:
    $key_679e = { 30 ec [2] 02 ce [2] 04 fb [2] 2a fb [2] 15 e7 }

  condition:
    any of them
}