rule TTP_XOR_WriteProcessMemory_07dc {
  strings:
    $key_07dc = { 50 ae [2] 62 8c [2] 64 b9 [2] 4a b9 [2] 75 a5 }

  condition:
    any of them
}