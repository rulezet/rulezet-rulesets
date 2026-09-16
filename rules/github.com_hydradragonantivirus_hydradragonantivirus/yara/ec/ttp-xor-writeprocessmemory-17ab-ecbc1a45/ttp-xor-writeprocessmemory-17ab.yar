rule TTP_XOR_WriteProcessMemory_17ab {
  strings:
    $key_17ab = { 40 d9 [2] 72 fb [2] 74 ce [2] 5a ce [2] 65 d2 }

  condition:
    any of them
}