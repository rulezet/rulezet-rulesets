rule TTP_XOR_WriteProcessMemory_01ab {
  strings:
    $key_01ab = { 56 d9 [2] 64 fb [2] 62 ce [2] 4c ce [2] 73 d2 }

  condition:
    any of them
}