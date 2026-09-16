rule TTP_XOR_WriteProcessMemory_25bc {
  strings:
    $key_25bc = { 72 ce [2] 40 ec [2] 46 d9 [2] 68 d9 [2] 57 c5 }

  condition:
    any of them
}