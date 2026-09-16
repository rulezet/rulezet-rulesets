rule TTP_XOR_WriteProcessMemory_6cdb {
  strings:
    $key_6cdb = { 3b a9 [2] 09 8b [2] 0f be [2] 21 be [2] 1e a2 }

  condition:
    any of them
}