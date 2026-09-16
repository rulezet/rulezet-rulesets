rule TTP_XOR_WriteProcessMemory_bb9e {
  strings:
    $key_bb9e = { ec ec [2] de ce [2] d8 fb [2] f6 fb [2] c9 e7 }

  condition:
    any of them
}