rule TTP_XOR_WriteProcessMemory_1ddb {
  strings:
    $key_1ddb = { 4a a9 [2] 78 8b [2] 7e be [2] 50 be [2] 6f a2 }

  condition:
    any of them
}