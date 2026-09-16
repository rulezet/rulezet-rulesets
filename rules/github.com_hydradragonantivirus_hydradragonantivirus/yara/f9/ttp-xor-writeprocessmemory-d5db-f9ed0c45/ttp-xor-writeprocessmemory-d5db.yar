rule TTP_XOR_WriteProcessMemory_d5db {
  strings:
    $key_d5db = { 82 a9 [2] b0 8b [2] b6 be [2] 98 be [2] a7 a2 }

  condition:
    any of them
}