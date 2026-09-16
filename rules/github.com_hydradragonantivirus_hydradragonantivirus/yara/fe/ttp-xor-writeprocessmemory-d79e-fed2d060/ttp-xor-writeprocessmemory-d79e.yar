rule TTP_XOR_WriteProcessMemory_d79e {
  strings:
    $key_d79e = { 80 ec [2] b2 ce [2] b4 fb [2] 9a fb [2] a5 e7 }

  condition:
    any of them
}