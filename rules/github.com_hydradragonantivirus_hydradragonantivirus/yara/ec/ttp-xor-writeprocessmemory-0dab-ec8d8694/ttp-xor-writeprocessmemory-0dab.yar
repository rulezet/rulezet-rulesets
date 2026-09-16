rule TTP_XOR_WriteProcessMemory_0dab {
  strings:
    $key_0dab = { 5a d9 [2] 68 fb [2] 6e ce [2] 40 ce [2] 7f d2 }

  condition:
    any of them
}