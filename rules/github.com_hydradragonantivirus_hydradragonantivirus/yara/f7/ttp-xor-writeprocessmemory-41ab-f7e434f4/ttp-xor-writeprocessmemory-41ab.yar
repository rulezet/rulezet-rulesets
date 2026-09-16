rule TTP_XOR_WriteProcessMemory_41ab {
  strings:
    $key_41ab = { 16 d9 [2] 24 fb [2] 22 ce [2] 0c ce [2] 33 d2 }

  condition:
    any of them
}