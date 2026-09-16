rule TTP_XOR_WriteProcessMemory_02dc {
  strings:
    $key_02dc = { 55 ae [2] 67 8c [2] 61 b9 [2] 4f b9 [2] 70 a5 }

  condition:
    any of them
}