rule TTP_XOR_WriteProcessMemory_f49e {
  strings:
    $key_f49e = { a3 ec [2] 91 ce [2] 97 fb [2] b9 fb [2] 86 e7 }

  condition:
    any of them
}