rule TTP_XOR_WriteProcessMemory_d49e {
  strings:
    $key_d49e = { 83 ec [2] b1 ce [2] b7 fb [2] 99 fb [2] a6 e7 }

  condition:
    any of them
}