rule TTP_XOR_WriteProcessMemory_1fdb {
  strings:
    $key_1fdb = { 48 a9 [2] 7a 8b [2] 7c be [2] 52 be [2] 6d a2 }

  condition:
    any of them
}