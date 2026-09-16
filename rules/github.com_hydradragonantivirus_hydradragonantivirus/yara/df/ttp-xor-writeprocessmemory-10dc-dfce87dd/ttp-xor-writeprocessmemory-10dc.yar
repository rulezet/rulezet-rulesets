rule TTP_XOR_WriteProcessMemory_10dc {
  strings:
    $key_10dc = { 47 ae [2] 75 8c [2] 73 b9 [2] 5d b9 [2] 62 a5 }

  condition:
    any of them
}