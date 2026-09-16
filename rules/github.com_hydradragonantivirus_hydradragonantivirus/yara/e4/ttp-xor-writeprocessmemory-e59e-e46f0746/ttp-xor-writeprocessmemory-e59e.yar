rule TTP_XOR_WriteProcessMemory_e59e {
  strings:
    $key_e59e = { b2 ec [2] 80 ce [2] 86 fb [2] a8 fb [2] 97 e7 }

  condition:
    any of them
}