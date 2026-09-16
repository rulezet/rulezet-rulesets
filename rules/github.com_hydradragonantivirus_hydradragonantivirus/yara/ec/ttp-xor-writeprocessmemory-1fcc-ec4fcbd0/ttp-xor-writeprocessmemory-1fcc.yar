rule TTP_XOR_WriteProcessMemory_1fcc {
  strings:
    $key_1fcc = { 48 be [2] 7a 9c [2] 7c a9 [2] 52 a9 [2] 6d b5 }

  condition:
    any of them
}