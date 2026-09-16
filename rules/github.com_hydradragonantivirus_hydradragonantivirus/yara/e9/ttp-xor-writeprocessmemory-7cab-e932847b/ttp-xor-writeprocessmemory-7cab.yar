rule TTP_XOR_WriteProcessMemory_7cab {
  strings:
    $key_7cab = { 2b d9 [2] 19 fb [2] 1f ce [2] 31 ce [2] 0e d2 }

  condition:
    any of them
}