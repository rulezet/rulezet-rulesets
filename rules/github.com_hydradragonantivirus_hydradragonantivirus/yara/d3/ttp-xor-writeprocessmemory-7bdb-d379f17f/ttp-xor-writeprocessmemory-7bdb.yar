rule TTP_XOR_WriteProcessMemory_7bdb {
  strings:
    $key_7bdb = { 2c a9 [2] 1e 8b [2] 18 be [2] 36 be [2] 09 a2 }

  condition:
    any of them
}