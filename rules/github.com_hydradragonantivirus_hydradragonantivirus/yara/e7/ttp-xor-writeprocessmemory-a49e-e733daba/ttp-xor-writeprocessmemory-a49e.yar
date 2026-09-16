rule TTP_XOR_WriteProcessMemory_a49e {
  strings:
    $key_a49e = { f3 ec [2] c1 ce [2] c7 fb [2] e9 fb [2] d6 e7 }

  condition:
    any of them
}