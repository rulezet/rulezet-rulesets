rule TTP_XOR_WriteProcessMemory_4cdb {
  strings:
    $key_4cdb = { 1b a9 [2] 29 8b [2] 2f be [2] 01 be [2] 3e a2 }

  condition:
    any of them
}