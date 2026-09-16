rule TTP_XOR_WriteProcessMemory_72db {
  strings:
    $key_72db = { 25 a9 [2] 17 8b [2] 11 be [2] 3f be [2] 00 a2 }

  condition:
    any of them
}