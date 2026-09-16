rule TTP_XOR_WriteProcessMemory_5fcb {
  strings:
    $key_5fcb = { 08 b9 [2] 3a 9b [2] 3c ae [2] 12 ae [2] 2d b2 }

  condition:
    any of them
}