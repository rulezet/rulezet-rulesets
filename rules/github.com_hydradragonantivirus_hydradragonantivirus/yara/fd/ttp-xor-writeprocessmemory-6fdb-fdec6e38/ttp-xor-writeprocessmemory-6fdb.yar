rule TTP_XOR_WriteProcessMemory_6fdb {
  strings:
    $key_6fdb = { 38 a9 [2] 0a 8b [2] 0c be [2] 22 be [2] 1d a2 }

  condition:
    any of them
}