rule TTP_XOR_WriteProcessMemory_eaab {
  strings:
    $key_eaab = { bd d9 [2] 8f fb [2] 89 ce [2] a7 ce [2] 98 d2 }

  condition:
    any of them
}