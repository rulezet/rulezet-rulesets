rule TTP_XOR_WriteProcessMemory_50ab {
  strings:
    $key_50ab = { 07 d9 [2] 35 fb [2] 33 ce [2] 1d ce [2] 22 d2 }

  condition:
    any of them
}