rule TTP_XOR_WriteProcessMemory_54ab {
  strings:
    $key_54ab = { 03 d9 [2] 31 fb [2] 37 ce [2] 19 ce [2] 26 d2 }

  condition:
    any of them
}