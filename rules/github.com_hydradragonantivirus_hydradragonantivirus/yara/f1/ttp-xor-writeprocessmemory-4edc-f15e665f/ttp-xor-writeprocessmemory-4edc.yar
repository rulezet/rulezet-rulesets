rule TTP_XOR_WriteProcessMemory_4edc {
  strings:
    $key_4edc = { 19 ae [2] 2b 8c [2] 2d b9 [2] 03 b9 [2] 3c a5 }

  condition:
    any of them
}