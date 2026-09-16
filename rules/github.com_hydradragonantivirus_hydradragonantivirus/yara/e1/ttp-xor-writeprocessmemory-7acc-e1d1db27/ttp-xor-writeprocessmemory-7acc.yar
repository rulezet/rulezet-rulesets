rule TTP_XOR_WriteProcessMemory_7acc {
  strings:
    $key_7acc = { 2d be [2] 1f 9c [2] 19 a9 [2] 37 a9 [2] 08 b5 }

  condition:
    any of them
}