rule TTP_XOR_WriteProcessMemory_43bc {
  strings:
    $key_43bc = { 14 ce [2] 26 ec [2] 20 d9 [2] 0e d9 [2] 31 c5 }

  condition:
    any of them
}