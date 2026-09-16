rule TTP_XOR_WriteProcessMemory_dacc {
  strings:
    $key_dacc = { 8d be [2] bf 9c [2] b9 a9 [2] 97 a9 [2] a8 b5 }

  condition:
    any of them
}