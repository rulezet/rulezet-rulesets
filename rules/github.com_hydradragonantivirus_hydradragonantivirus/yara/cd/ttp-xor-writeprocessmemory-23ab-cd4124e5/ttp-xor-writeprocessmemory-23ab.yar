rule TTP_XOR_WriteProcessMemory_23ab {
  strings:
    $key_23ab = { 74 d9 [2] 46 fb [2] 40 ce [2] 6e ce [2] 51 d2 }

  condition:
    any of them
}