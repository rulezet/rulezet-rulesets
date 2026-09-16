rule TTP_XOR_WriteProcessMemory_619e {
  strings:
    $key_619e = { 36 ec [2] 04 ce [2] 02 fb [2] 2c fb [2] 13 e7 }

  condition:
    any of them
}