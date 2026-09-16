rule TTP_XOR_WriteProcessMemory_10ab {
  strings:
    $key_10ab = { 47 d9 [2] 75 fb [2] 73 ce [2] 5d ce [2] 62 d2 }

  condition:
    any of them
}