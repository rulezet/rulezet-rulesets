rule TTP_XOR_WriteProcessMemory_8d9e {
  strings:
    $key_8d9e = { da ec [2] e8 ce [2] ee fb [2] c0 fb [2] ff e7 }

  condition:
    any of them
}