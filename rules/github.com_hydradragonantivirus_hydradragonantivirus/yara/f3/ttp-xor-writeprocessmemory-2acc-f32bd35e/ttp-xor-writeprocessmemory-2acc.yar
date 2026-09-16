rule TTP_XOR_WriteProcessMemory_2acc {
  strings:
    $key_2acc = { 7d be [2] 4f 9c [2] 49 a9 [2] 67 a9 [2] 58 b5 }

  condition:
    any of them
}