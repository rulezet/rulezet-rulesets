rule TTP_XOR_WriteProcessMemory_02db {
  strings:
    $key_02db = { 55 a9 [2] 67 8b [2] 61 be [2] 4f be [2] 70 a2 }

  condition:
    any of them
}