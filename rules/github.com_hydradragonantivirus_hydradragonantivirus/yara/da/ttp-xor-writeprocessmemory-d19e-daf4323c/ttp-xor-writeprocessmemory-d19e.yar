rule TTP_XOR_WriteProcessMemory_d19e {
  strings:
    $key_d19e = { 86 ec [2] b4 ce [2] b2 fb [2] 9c fb [2] a3 e7 }

  condition:
    any of them
}