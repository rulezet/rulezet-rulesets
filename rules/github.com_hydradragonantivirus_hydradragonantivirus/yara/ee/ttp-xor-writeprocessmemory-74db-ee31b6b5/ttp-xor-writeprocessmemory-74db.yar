rule TTP_XOR_WriteProcessMemory_74db {
  strings:
    $key_74db = { 23 a9 [2] 11 8b [2] 17 be [2] 39 be [2] 06 a2 }

  condition:
    any of them
}