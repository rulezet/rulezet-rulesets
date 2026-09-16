rule TTP_XOR_WriteProcessMemory_22dc {
  strings:
    $key_22dc = { 75 ae [2] 47 8c [2] 41 b9 [2] 6f b9 [2] 50 a5 }

  condition:
    any of them
}