rule TTP_XOR_WriteProcessMemory_a3ab {
  strings:
    $key_a3ab = { f4 d9 [2] c6 fb [2] c0 ce [2] ee ce [2] d1 d2 }

  condition:
    any of them
}