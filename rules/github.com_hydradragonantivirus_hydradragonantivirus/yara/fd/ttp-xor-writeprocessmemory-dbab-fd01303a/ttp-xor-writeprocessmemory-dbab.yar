rule TTP_XOR_WriteProcessMemory_dbab {
  strings:
    $key_dbab = { 8c d9 [2] be fb [2] b8 ce [2] 96 ce [2] a9 d2 }

  condition:
    any of them
}