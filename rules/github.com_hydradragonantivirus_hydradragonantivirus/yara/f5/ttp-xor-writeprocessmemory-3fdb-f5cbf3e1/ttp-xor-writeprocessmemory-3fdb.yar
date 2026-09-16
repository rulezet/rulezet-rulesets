rule TTP_XOR_WriteProcessMemory_3fdb {
  strings:
    $key_3fdb = { 68 a9 [2] 5a 8b [2] 5c be [2] 72 be [2] 4d a2 }

  condition:
    any of them
}