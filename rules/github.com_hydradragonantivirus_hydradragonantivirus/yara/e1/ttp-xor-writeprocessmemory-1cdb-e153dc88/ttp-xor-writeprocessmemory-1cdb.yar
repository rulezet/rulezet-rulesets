rule TTP_XOR_WriteProcessMemory_1cdb {
  strings:
    $key_1cdb = { 4b a9 [2] 79 8b [2] 7f be [2] 51 be [2] 6e a2 }

  condition:
    any of them
}