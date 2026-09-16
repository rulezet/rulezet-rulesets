rule TTP_XOR_WriteProcessMemory_43ab {
  strings:
    $key_43ab = { 14 d9 [2] 26 fb [2] 20 ce [2] 0e ce [2] 31 d2 }

  condition:
    any of them
}