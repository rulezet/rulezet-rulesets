rule TTP_XOR_WriteProcessMemory_8dab {
  strings:
    $key_8dab = { da d9 [2] e8 fb [2] ee ce [2] c0 ce [2] ff d2 }

  condition:
    any of them
}