rule TTP_XOR_WriteProcessMemory_61ab {
  strings:
    $key_61ab = { 36 d9 [2] 04 fb [2] 02 ce [2] 2c ce [2] 13 d2 }

  condition:
    any of them
}