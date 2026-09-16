rule TTP_XOR_WriteProcessMemory_b49e {
  strings:
    $key_b49e = { e3 ec [2] d1 ce [2] d7 fb [2] f9 fb [2] c6 e7 }

  condition:
    any of them
}