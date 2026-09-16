rule TTP_XOR_WriteProcessMemory_d4db {
  strings:
    $key_d4db = { 83 a9 [2] b1 8b [2] b7 be [2] 99 be [2] a6 a2 }

  condition:
    any of them
}