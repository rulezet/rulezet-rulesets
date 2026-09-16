rule TTP_XOR_WriteProcessMemory_71dc {
  strings:
    $key_71dc = { 26 ae [2] 14 8c [2] 12 b9 [2] 3c b9 [2] 03 a5 }

  condition:
    any of them
}