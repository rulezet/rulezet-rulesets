rule TTP_XOR_WriteProcessMemory_30dc {
  strings:
    $key_30dc = { 67 ae [2] 55 8c [2] 53 b9 [2] 7d b9 [2] 42 a5 }

  condition:
    any of them
}