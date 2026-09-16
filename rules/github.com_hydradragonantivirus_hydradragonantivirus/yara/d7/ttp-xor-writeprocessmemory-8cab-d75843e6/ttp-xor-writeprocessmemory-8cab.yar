rule TTP_XOR_WriteProcessMemory_8cab {
  strings:
    $key_8cab = { db d9 [2] e9 fb [2] ef ce [2] c1 ce [2] fe d2 }

  condition:
    any of them
}