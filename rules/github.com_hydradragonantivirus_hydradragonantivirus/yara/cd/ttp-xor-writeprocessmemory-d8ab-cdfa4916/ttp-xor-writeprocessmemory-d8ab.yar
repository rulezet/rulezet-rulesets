rule TTP_XOR_WriteProcessMemory_d8ab {
  strings:
    $key_d8ab = { 8f d9 [2] bd fb [2] bb ce [2] 95 ce [2] aa d2 }

  condition:
    any of them
}