rule TTP_XOR_WriteProcessMemory_d39e {
  strings:
    $key_d39e = { 84 ec [2] b6 ce [2] b0 fb [2] 9e fb [2] a1 e7 }

  condition:
    any of them
}