rule TTP_XOR_WriteProcessMemory_66db {
  strings:
    $key_66db = { 31 a9 [2] 03 8b [2] 05 be [2] 2b be [2] 14 a2 }

  condition:
    any of them
}