rule TTP_XOR_WriteProcessMemory_56ab {
  strings:
    $key_56ab = { 01 d9 [2] 33 fb [2] 35 ce [2] 1b ce [2] 24 d2 }

  condition:
    any of them
}