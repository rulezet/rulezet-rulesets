rule TTP_XOR_WriteProcessMemory_33db {
  strings:
    $key_33db = { 64 a9 [2] 56 8b [2] 50 be [2] 7e be [2] 41 a2 }

  condition:
    any of them
}