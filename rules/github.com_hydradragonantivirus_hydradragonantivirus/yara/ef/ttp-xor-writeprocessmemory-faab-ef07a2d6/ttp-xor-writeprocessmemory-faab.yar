rule TTP_XOR_WriteProcessMemory_faab {
  strings:
    $key_faab = { ad d9 [2] 9f fb [2] 99 ce [2] b7 ce [2] 88 d2 }

  condition:
    any of them
}