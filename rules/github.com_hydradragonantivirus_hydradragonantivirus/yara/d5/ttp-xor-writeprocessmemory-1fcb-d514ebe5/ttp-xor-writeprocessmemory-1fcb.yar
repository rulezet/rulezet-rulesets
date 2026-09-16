rule TTP_XOR_WriteProcessMemory_1fcb {
  strings:
    $key_1fcb = { 48 b9 [2] 7a 9b [2] 7c ae [2] 52 ae [2] 6d b2 }

  condition:
    any of them
}