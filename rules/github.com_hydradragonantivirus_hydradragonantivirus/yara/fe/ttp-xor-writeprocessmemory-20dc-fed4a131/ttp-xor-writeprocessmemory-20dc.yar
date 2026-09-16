rule TTP_XOR_WriteProcessMemory_20dc {
  strings:
    $key_20dc = { 77 ae [2] 45 8c [2] 43 b9 [2] 6d b9 [2] 52 a5 }

  condition:
    any of them
}