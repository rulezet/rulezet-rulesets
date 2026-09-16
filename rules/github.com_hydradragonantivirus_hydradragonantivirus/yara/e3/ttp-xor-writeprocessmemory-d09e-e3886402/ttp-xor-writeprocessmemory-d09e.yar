rule TTP_XOR_WriteProcessMemory_d09e {
  strings:
    $key_d09e = { 87 ec [2] b5 ce [2] b3 fb [2] 9d fb [2] a2 e7 }

  condition:
    any of them
}