rule TTP_XOR_WriteProcessMemory_44ab {
  strings:
    $key_44ab = { 13 d9 [2] 21 fb [2] 27 ce [2] 09 ce [2] 36 d2 }

  condition:
    any of them
}