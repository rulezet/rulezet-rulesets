rule TTP_XOR_WriteProcessMemory_23dc {
  strings:
    $key_23dc = { 74 ae [2] 46 8c [2] 40 b9 [2] 6e b9 [2] 51 a5 }

  condition:
    any of them
}