rule TTP_XOR_WriteProcessMemory_929e {
  strings:
    $key_929e = { c5 ec [2] f7 ce [2] f1 fb [2] df fb [2] e0 e7 }

  condition:
    any of them
}