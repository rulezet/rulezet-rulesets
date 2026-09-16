rule TTP_XOR_WriteProcessMemory_34db {
  strings:
    $key_34db = { 63 a9 [2] 51 8b [2] 57 be [2] 79 be [2] 46 a2 }

  condition:
    any of them
}